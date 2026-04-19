from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from trace.classify import classify_case
from trace.ingest import ingest_case
from trace.report import compute_findings
from trace.storage import read_json, write_json


@dataclass
class ValidationResult:
    reference_name: str
    profile: str
    behavioral_agreement: float
    vulnerability_agreement: float
    findings_match: bool
    pass_thresholds: bool
    elapsed_seconds: float


def run_validation(reference_path: Path, working_root: Path, profile: str = "heuristic") -> ValidationResult:
    start = perf_counter()
    reference = read_json(reference_path)
    case_id = reference["case_id"]
    case_root = working_root / "cases"
    ingest_case(reference_path, case_id, "validator", "json", case_root)
    classify_kwargs = {}
    if profile == "hosted":
        classify_kwargs = {"provider": "mock", "model": "benchmark-mock-model", "window_size": 8}
    classify_case(case_root / case_id, "validator", **classify_kwargs)
    classified = read_json(case_root / case_id / "classified_transcript.json")
    transcript = classified["transcript"]
    expected = reference["expected"]

    behavior_total = 0
    behavior_match = 0
    vulnerability_total = 0
    vulnerability_match = 0
    for actual, target in zip(transcript, expected["transcript"], strict=True):
        if actual["speaker"] == "system":
            behavior_total += 1
            if actual["classification"]["behavioral_category"] == target["behavioral_category"]:
                behavior_match += 1
        else:
            vulnerability_total += 1
            if actual["classification"]["vulnerability_level"] == target["vulnerability_level"]:
                vulnerability_match += 1
    findings = compute_findings(transcript)
    findings_match = (
        round(findings["inappropriate_response_rate"], 1) == round(expected["inappropriate_response_rate"], 1)
        and round(findings["crisis_failure_rate"], 1) == round(expected["crisis_failure_rate"], 1)
    )
    behavioral_agreement = (behavior_match / behavior_total * 100) if behavior_total else 100.0
    vulnerability_agreement = (vulnerability_match / vulnerability_total * 100) if vulnerability_total else 100.0
    pass_thresholds = behavioral_agreement >= 80.0 and vulnerability_agreement >= 85.0 and findings_match
    elapsed_seconds = round(perf_counter() - start, 4)
    return ValidationResult(
        reference_name=reference_path.name,
        profile=profile,
        behavioral_agreement=behavioral_agreement,
        vulnerability_agreement=vulnerability_agreement,
        findings_match=findings_match,
        pass_thresholds=pass_thresholds,
        elapsed_seconds=elapsed_seconds,
    )


def discover_reference_fixtures(validation_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in validation_dir.glob("*.json")
        if path.name.startswith("reference_") or path.name == "companion_incident.json"
    )


def render_benchmark_markdown(summary: dict) -> str:
    lines = [
        "# TRACE Benchmark Summary\n\n",
        f"- Profile: `{summary['profile']}`\n",
        f"- Fixtures: `{summary['total_fixtures']}`\n",
        f"- Passed: `{summary['passed_fixtures']}`\n",
        f"- Failed: `{summary['failed_fixtures']}`\n",
        f"- Pass Rate: `{summary['pass_rate']}%`\n",
        f"- Total Time: `{summary['total_elapsed_seconds']}` seconds\n\n",
        "| Reference | Profile | Behavioral | Vulnerability | Findings Match | Pass | Time (s) |\n",
        "|---|---|---:|---:|---|---|---:|\n",
    ]
    for result in summary["results"]:
        lines.append(
            f"| `{result['reference_name']}` | `{result['profile']}` | "
            f"`{result['behavioral_agreement']:.1f}%` | `{result['vulnerability_agreement']:.1f}%` | "
            f"`{result['findings_match']}` | `{result['pass_thresholds']}` | `{result['elapsed_seconds']}` |\n"
        )
    return "".join(lines)


def write_benchmark_artifacts(summary: dict, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark_summary.json"
    md_path = output_dir / "benchmark_summary.md"
    write_json(json_path, summary)
    md_path.write_text(render_benchmark_markdown(summary), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def run_benchmark_suite(validation_dir: Path, working_root: Path, profile: str = "heuristic") -> dict:
    fixtures = discover_reference_fixtures(validation_dir)
    results = []
    for fixture in fixtures:
        result = run_validation(fixture, working_root / fixture.stem, profile=profile)
        results.append(asdict(result))
    total = len(results)
    passed = sum(1 for result in results if result["pass_thresholds"])
    total_elapsed = round(sum(result["elapsed_seconds"] for result in results), 4)
    return {
        "profile": profile,
        "total_fixtures": total,
        "passed_fixtures": passed,
        "failed_fixtures": total - passed,
        "pass_rate": round((passed / total * 100), 2) if total else 0.0,
        "total_elapsed_seconds": total_elapsed,
        "results": results,
    }
