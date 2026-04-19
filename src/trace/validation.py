from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess
from time import perf_counter

from trace.classify import classify_case
from trace.ingest import ingest_case
from trace.report import compute_findings
from trace.storage import read_json, utc_now_iso, write_json


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


def compare_benchmark_summaries(baseline: dict, candidate: dict) -> dict:
    baseline_results = {item["reference_name"]: item for item in baseline["results"]}
    candidate_results = {item["reference_name"]: item for item in candidate["results"]}
    references = sorted(set(baseline_results) & set(candidate_results))
    comparisons = []
    drift_count = 0
    for reference_name in references:
        left = baseline_results[reference_name]
        right = candidate_results[reference_name]
        behavior_delta = round(right["behavioral_agreement"] - left["behavioral_agreement"], 4)
        vulnerability_delta = round(right["vulnerability_agreement"] - left["vulnerability_agreement"], 4)
        findings_changed = right["findings_match"] != left["findings_match"]
        threshold_changed = right["pass_thresholds"] != left["pass_thresholds"]
        drift_detected = (
            behavior_delta != 0.0
            or vulnerability_delta != 0.0
            or findings_changed
            or threshold_changed
        )
        if drift_detected:
            drift_count += 1
        comparisons.append(
            {
                "reference_name": reference_name,
                "baseline_profile": baseline["profile"],
                "candidate_profile": candidate["profile"],
                "behavioral_delta": behavior_delta,
                "vulnerability_delta": vulnerability_delta,
                "findings_changed": findings_changed,
                "threshold_changed": threshold_changed,
                "drift_detected": drift_detected,
                "baseline_pass": left["pass_thresholds"],
                "candidate_pass": right["pass_thresholds"],
            }
        )
    return {
        "baseline_profile": baseline["profile"],
        "candidate_profile": candidate["profile"],
        "references_compared": len(comparisons),
        "drift_count": drift_count,
        "drift_free": drift_count == 0,
        "comparisons": comparisons,
    }


def render_comparison_markdown(comparison: dict) -> str:
    lines = [
        "# TRACE Benchmark Comparison\n\n",
        f"- Baseline Profile: `{comparison['baseline_profile']}`\n",
        f"- Candidate Profile: `{comparison['candidate_profile']}`\n",
        f"- References Compared: `{comparison['references_compared']}`\n",
        f"- Drift Count: `{comparison['drift_count']}`\n",
        f"- Drift Free: `{comparison['drift_free']}`\n\n",
        "| Reference | Behavioral Δ | Vulnerability Δ | Findings Changed | Threshold Changed | Drift |\n",
        "|---|---:|---:|---|---|---|\n",
    ]
    for item in comparison["comparisons"]:
        lines.append(
            f"| `{item['reference_name']}` | `{item['behavioral_delta']}` | `{item['vulnerability_delta']}` | "
            f"`{item['findings_changed']}` | `{item['threshold_changed']}` | `{item['drift_detected']}` |\n"
        )
    return "".join(lines)


def write_benchmark_artifacts(summary: dict, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark_summary.json"
    md_path = output_dir / "benchmark_summary.md"
    write_json(json_path, summary)
    md_path.write_text(render_benchmark_markdown(summary), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def write_comparison_artifacts(comparison: dict, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark_comparison.json"
    md_path = output_dir / "benchmark_comparison.md"
    write_json(json_path, comparison)
    md_path.write_text(render_comparison_markdown(comparison), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def write_artifact_history_snapshot(payload: dict, history_dir: Path, label: str) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    safe_label = label.replace("/", "_").replace(" ", "_")
    timestamp = utc_now_iso().replace(":", "-").replace("+00:00", "Z")
    snapshot = {
        "label": safe_label,
        "generated_at": utc_now_iso(),
        "payload": payload,
    }
    latest_path = history_dir / f"{safe_label}.json"
    dated_path = history_dir / f"{safe_label}_{timestamp}.json"
    write_json(latest_path, snapshot)
    write_json(dated_path, snapshot)
    return {"latest": latest_path, "dated": dated_path}


def sign_artifact_bundle(
    output_dir: Path,
    private_key_path: Path,
    public_key_path: Path,
    signer_label: str,
    signing_certificate_path: Path | None = None,
    certificate_chain_paths: list[Path] | None = None,
) -> dict:
    manifest_path = output_dir / "artifact_manifest.json"
    signature_path = output_dir / "artifact_manifest.sig"
    trust_path = output_dir / "artifact_trust.json"
    files = []
    for path in sorted(p for p in output_dir.iterdir() if p.is_file() and p.name not in {manifest_path.name, signature_path.name, trust_path.name}):
        files.append({"path": path.name, "sha256": hash_file(path)})
    manifest = {
        "generated_at": utc_now_iso(),
        "signer_label": signer_label,
        "files": files,
    }
    write_json(manifest_path, manifest)
    subprocess.run(
        [
            "openssl", "dgst", "-sha256", "-sign", str(private_key_path),
            "-out", str(signature_path), str(manifest_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    trust = {
        "signer_label": signer_label,
        "public_key_path": public_key_path.name,
        "public_key_sha256": hash_file(public_key_path),
        "signing_certificate_path": signing_certificate_path.name if signing_certificate_path else None,
        "certificate_chain": [],
    }
    target_public_key = output_dir / public_key_path.name
    if public_key_path.resolve() != target_public_key.resolve():
        target_public_key.write_bytes(public_key_path.read_bytes())
    if signing_certificate_path and signing_certificate_path.exists():
        target_cert = output_dir / signing_certificate_path.name
        if signing_certificate_path.resolve() != target_cert.resolve():
            target_cert.write_bytes(signing_certificate_path.read_bytes())
    for chain_path in certificate_chain_paths or []:
        target_chain = output_dir / chain_path.name
        if chain_path.resolve() != target_chain.resolve():
            target_chain.write_bytes(chain_path.read_bytes())
        trust["certificate_chain"].append({"path": chain_path.name, "sha256": hash_file(target_chain)})
    write_json(trust_path, trust)
    return {"manifest": manifest_path, "signature": signature_path, "trust": trust_path}


def verify_artifact_bundle(output_dir: Path, public_key_path: Path) -> dict:
    manifest_path = output_dir / "artifact_manifest.json"
    signature_path = output_dir / "artifact_manifest.sig"
    trust_path = output_dir / "artifact_trust.json"
    result = {
        "manifest_present": manifest_path.exists(),
        "signature_present": signature_path.exists(),
        "trust_present": trust_path.exists(),
        "signature_valid": False,
        "file_hashes_match": False,
        "trust_public_key_match": False,
    }
    if not manifest_path.exists() or not signature_path.exists():
        result["all_pass"] = False
        return result
    completed = subprocess.run(
        [
            "openssl", "dgst", "-sha256", "-verify", str(public_key_path),
            "-signature", str(signature_path), str(manifest_path),
        ],
        capture_output=True,
        text=True,
    )
    result["signature_valid"] = completed.returncode == 0
    manifest = read_json(manifest_path)
    result["file_hashes_match"] = all(
        (output_dir / item["path"]).exists() and hash_file(output_dir / item["path"]) == item["sha256"]
        for item in manifest.get("files", [])
    )
    if trust_path.exists():
        trust = read_json(trust_path)
        result["trust_public_key_match"] = trust.get("public_key_sha256") == hash_file(public_key_path)
    result["all_pass"] = result["signature_valid"] and result["file_hashes_match"] and (not result["trust_present"] or result["trust_public_key_match"])
    return result


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
