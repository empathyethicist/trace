from __future__ import annotations

import argparse
import os
from pathlib import Path
from urllib.parse import urlparse

from trace_forensics import __version__
from trace_forensics.classify import classify_case
from trace_forensics.ingest import ingest_case
from trace_forensics.irr import compute_irr, import_second_coder
from trace_forensics.report import (
    export_case_report,
    sign_manifest,
    verify_evidence_package,
    verify_manifest_signature,
    verify_signing_certificate,
)
from trace_forensics.validation import (
    apply_comparison_assessments,
    benchmark_profile_settings,
    build_history_trend_summary,
    compare_benchmark_summaries,
    collect_history_snapshots,
    normalize_benchmark_profile,
    run_benchmark_suite,
    run_validation,
    sign_artifact_bundle,
    verify_artifact_bundle,
    write_benchmark_artifacts,
    write_comparison_artifacts,
    write_artifact_history_snapshot,
    write_history_summary,
    write_history_trend_summary,
)


DEFAULT_ROOT = Path.cwd() / ".trace_data"


def evaluate_config(provider: str, model: str | None = None) -> dict:
    issues: list[str] = []
    notes: list[str] = []
    effective_model = model or os.environ.get("TRACE_HOSTED_MODEL") or "provider-default"
    hosted_adapter = os.environ.get("TRACE_HOSTED_ADAPTER", "openai-compatible").strip().lower()
    payload = {
        "provider": provider,
        "ready": True,
        "issues": issues,
        "notes": notes,
        "effective_model": effective_model if provider in {"hosted", "live-hosted"} else None,
        "hosted_adapter": hosted_adapter if provider in {"hosted", "live-hosted"} else None,
    }
    if provider == "heuristic":
        notes.append("Deterministic local heuristic path is available without additional configuration.")
        return payload
    if provider == "mock":
        notes.append("Mock provider path is available for local testing without external dependencies.")
        return payload
    if provider == "ollama":
        endpoint = os.environ.get("TRACE_LOCAL_RUNTIME_BASE_URL", "http://localhost:11434/api/generate")
        payload["local_runtime_base_url"] = endpoint
        notes.append("Local runtime path expects an Ollama-compatible generate endpoint unless TRACE_LOCAL_RUNTIME_BASE_URL is overridden.")
        return payload
    if provider in {"hosted", "live-hosted"}:
        api_key = os.environ.get("TRACE_HOSTED_API_KEY")
        base_url = os.environ.get("TRACE_HOSTED_BASE_URL")
        payload["hosted_base_url"] = base_url
        if hosted_adapter not in {"openai-compatible", "anthropic-messages"}:
            issues.append("TRACE_HOSTED_ADAPTER must be one of: anthropic-messages, openai-compatible.")
        if not api_key:
            issues.append("TRACE_HOSTED_API_KEY is not set.")
        if not base_url:
            issues.append("TRACE_HOSTED_BASE_URL is not set.")
        else:
            parsed = urlparse(base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                issues.append("TRACE_HOSTED_BASE_URL must be a valid http(s) URL.")
            elif not parsed.path:
                notes.append("TRACE_HOSTED_BASE_URL should target the adapter-specific API endpoint explicitly.")
        if hosted_adapter == "openai-compatible":
            notes.append("Hosted provider path expects an OpenAI-compatible chat-completions API contract.")
        elif hosted_adapter == "anthropic-messages":
            notes.append("Hosted provider path expects an Anthropic-compatible messages API contract.")
        notes.append(f"Effective hosted model: {effective_model}")
        payload["ready"] = not issues
        return payload
    payload["ready"] = False
    issues.append(f"Unsupported provider: {provider}")
    return payload


def apply_runtime_provider_overrides(args: argparse.Namespace) -> None:
    override_map = {
        "hosted_api_key": "TRACE_HOSTED_API_KEY",
        "hosted_base_url": "TRACE_HOSTED_BASE_URL",
        "hosted_model": "TRACE_HOSTED_MODEL",
        "hosted_adapter": "TRACE_HOSTED_ADAPTER",
    }
    for attr, env_name in override_map.items():
        value = getattr(args, attr, None)
        if value:
            os.environ[env_name] = value


def add_hosted_override_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hosted-api-key")
    parser.add_argument("--hosted-base-url")
    parser.add_argument("--hosted-model")
    parser.add_argument("--hosted-adapter", choices=["openai-compatible", "anthropic-messages"])


def init_workspace(root: Path) -> dict:
    created: list[str] = []
    for relative in [
        "cases",
        "replay_artifacts",
        "benchmark_artifacts",
        "benchmark_history",
        "validation_runs",
        "evidence_exports",
        "keys",
    ]:
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        created.append(str(path))

    readme_path = root / "README.md"
    if not readme_path.exists():
        readme_path.write_text(
            "\n".join(
                [
                    "# TRACE Workspace",
                    "",
                    "Recommended usage:",
                    "",
                    "- `cases/` — ingested case material",
                    "- `replay_artifacts/` — hosted replay captures",
                    "- `benchmark_artifacts/` — benchmark outputs",
                    "- `benchmark_history/` — benchmark history snapshots",
                    "- `validation_runs/` — local validation working directories",
                    "- `evidence_exports/` — exported evidence packages",
                    "- `keys/` — local signing materials",
                    "",
                    "Typical first steps:",
                    "",
                    "1. `trace config-check --provider heuristic`",
                    "2. `trace config-check --provider hosted`",
                    "3. `trace validate --reference <reference-transcript.json> --root ./validation_runs`",
                    "",
                    "Note: provide a reference fixture path from the TRACE repo checkout or your own validation corpus.",
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        created.append(str(readme_path))

    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(
            "\n".join(
                [
                    ".DS_Store",
                    "__pycache__/",
                    "*.pyc",
                    ".env",
                    "keys/*.pem",
                    "keys/*.key",
                    "keys/*.crt",
                    "keys/*.csr",
                    "keys/*.srl",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        created.append(str(gitignore_path))

    return {"root": str(root), "created": created}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trace")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest")
    ingest.add_argument("--input", required=True)
    ingest.add_argument("--format", required=True, choices=["json", "csv", "text", "plain", "court", "axiom", "ufed"])
    ingest.add_argument("--case-id", required=True)
    ingest.add_argument("--examiner", required=True)
    ingest.add_argument("--root", default=str(DEFAULT_ROOT))

    init_cmd = sub.add_parser("init")
    init_cmd.add_argument("--root", default=str(DEFAULT_ROOT))

    classify = sub.add_parser("classify")
    classify.add_argument("--case-id", required=True)
    classify.add_argument("--examiner", default="trace")
    classify.add_argument("--root", default=str(DEFAULT_ROOT))
    classify.add_argument("--manual", action="store_true")
    classify.add_argument("--provider", default="heuristic", choices=["heuristic", "mock", "ollama", "hosted", "none"])
    classify.add_argument("--model", default="trace-heuristic-v1")
    classify.add_argument("--temperature", type=float, default=0.0)
    classify.add_argument("--window-size", type=int, default=20)
    classify.add_argument("--review-mode", default="auto", choices=["auto", "flag-low-confidence", "interactive"])
    classify.add_argument("--replay-dir")
    classify.add_argument("--replay-mode", default="off", choices=["off", "record", "record-and-replay", "replay-only"])
    add_hosted_override_args(classify)

    irr_import = sub.add_parser("irr-import")
    irr_import.add_argument("--case-id", required=True)
    irr_import.add_argument("--coder-2-file", required=True)
    irr_import.add_argument("--root", default=str(DEFAULT_ROOT))

    irr_compute = sub.add_parser("irr-compute")
    irr_compute.add_argument("--case-id", required=True)
    irr_compute.add_argument("--root", default=str(DEFAULT_ROOT))

    report = sub.add_parser("report")
    report.add_argument("--case-id", required=True)
    report.add_argument("--examiner", default="trace")
    report.add_argument("--output", required=True)
    report.add_argument("--examiner-notes-file")
    report.add_argument("--root", default=str(DEFAULT_ROOT))

    validate = sub.add_parser("validate")
    validate.add_argument("--reference", required=True)
    validate.add_argument("--root", default=str(DEFAULT_ROOT))

    config_check = sub.add_parser("config-check")
    config_check.add_argument("--provider", default="hosted", choices=["heuristic", "mock", "ollama", "hosted", "live-hosted"])
    config_check.add_argument("--model")
    add_hosted_override_args(config_check)

    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("--validation-dir", default=str(Path.cwd() / "validation"))
    benchmark.add_argument("--root", default=str(DEFAULT_ROOT))
    benchmark.add_argument("--profile", default="heuristic", choices=["heuristic", "mock-hosted", "hosted", "live-hosted"])
    benchmark.add_argument("--output-dir")
    benchmark.add_argument("--history-dir")
    benchmark.add_argument("--sign-private-key")
    benchmark.add_argument("--sign-public-key")
    benchmark.add_argument("--signer-label", default="TRACE benchmark signer")
    benchmark.add_argument("--signing-certificate")
    benchmark.add_argument("--certificate-chain", action="append", default=[])
    benchmark.add_argument("--replay-dir")
    benchmark.add_argument("--replay-mode", default="off", choices=["off", "record", "record-and-replay", "replay-only"])
    add_hosted_override_args(benchmark)

    compare = sub.add_parser("benchmark-compare")
    compare.add_argument("--validation-dir", default=str(Path.cwd() / "validation"))
    compare.add_argument("--root", default=str(DEFAULT_ROOT))
    compare.add_argument("--baseline-profile", default="heuristic", choices=["heuristic", "mock-hosted", "hosted", "live-hosted"])
    compare.add_argument("--candidate-profile", default="mock-hosted", choices=["heuristic", "mock-hosted", "hosted", "live-hosted"])
    compare.add_argument("--output-dir")
    compare.add_argument("--history-dir")
    compare.add_argument("--sign-private-key")
    compare.add_argument("--sign-public-key")
    compare.add_argument("--signer-label", default="TRACE benchmark signer")
    compare.add_argument("--signing-certificate")
    compare.add_argument("--certificate-chain", action="append", default=[])
    compare.add_argument("--replay-dir")
    compare.add_argument("--replay-mode", default="off", choices=["off", "record", "record-and-replay", "replay-only"])
    add_hosted_override_args(compare)

    benchmark_replay = sub.add_parser("benchmark-replay")
    benchmark_replay.add_argument("--validation-dir", default=str(Path.cwd() / "validation"))
    benchmark_replay.add_argument("--root", default=str(DEFAULT_ROOT))
    benchmark_replay.add_argument("--profile", default="live-hosted", choices=["mock-hosted", "hosted", "live-hosted"])
    benchmark_replay.add_argument("--replay-dir", required=True)
    benchmark_replay.add_argument("--output-dir")
    benchmark_replay.add_argument("--history-dir")
    benchmark_replay.add_argument("--sign-private-key")
    benchmark_replay.add_argument("--sign-public-key")
    benchmark_replay.add_argument("--signer-label", default="TRACE benchmark signer")
    benchmark_replay.add_argument("--signing-certificate")
    benchmark_replay.add_argument("--certificate-chain", action="append", default=[])
    add_hosted_override_args(benchmark_replay)

    verify = sub.add_parser("verify-package")
    verify.add_argument("--package", required=True)

    sign = sub.add_parser("sign-package")
    sign.add_argument("--package", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--public-key")
    sign.add_argument("--signer-label")
    sign.add_argument("--certificate-chain", action="append", default=[])
    sign.add_argument("--signing-certificate")

    verify_sig = sub.add_parser("verify-signature")
    verify_sig.add_argument("--package", required=True)
    verify_sig.add_argument("--public-key", required=True)
    verify_sig.add_argument("--ca-file")
    verify_sig.add_argument("--crl-file")

    history = sub.add_parser("benchmark-history")
    history.add_argument("--history-dir", required=True)
    history.add_argument("--prefix", required=True)

    trend = sub.add_parser("benchmark-trend")
    trend.add_argument("--history-dir", required=True)
    trend.add_argument("--prefix", required=True)

    sub.add_parser("version")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        result = ingest_case(Path(args.input), args.case_id, args.examiner, args.format, Path(args.root) / "cases")
        print(f"[INGEST] Source hash (SHA-256): {result.source_hash}")
        print(f"[INGEST] Messages: {result.transcript_count}")
        print(f"[INGEST] Case {args.case_id} ready for classification")
        return

    if args.command == "init":
        result = init_workspace(Path(args.root))
        print(f"[INIT] Workspace root: {result['root']}")
        for item in result["created"]:
            print(f"[INIT] Created: {item}")
        return

    if args.command == "classify":
        apply_runtime_provider_overrides(args)
        model = args.model
        if not args.manual and args.provider == "hosted":
            model = args.hosted_model or os.environ.get("TRACE_HOSTED_MODEL") or model
            if model == "trace-heuristic-v1":
                model = "provider-default"
        result = classify_case(
            Path(args.root) / "cases" / args.case_id,
            args.examiner,
            mode="manual" if args.manual else "heuristic",
            provider="none" if args.manual else args.provider,
            model="manual-human-review" if args.manual else model,
            temperature=args.temperature,
            window_size=args.window_size,
            review_mode=args.review_mode,
            replay_dir=Path(args.replay_dir) if args.replay_dir else None,
            replay_mode=args.replay_mode,
        )
        print(f"[CLASSIFY] Classified {result.message_count} messages")
        print(f"[CLASSIFY] Output: {result.classified_path}")
        return

    if args.command == "irr-import":
        path = import_second_coder(Path(args.root) / "cases" / args.case_id, Path(args.coder_2_file))
        print(f"[IRR] Imported second coder transcript to {path}")
        return

    if args.command == "irr-compute":
        stats = compute_irr(Path(args.root) / "cases" / args.case_id)
        for key, value in stats.items():
            print(f"[IRR] {key}: {value}")
        return

    if args.command == "report":
        examiner_notes = ""
        if args.examiner_notes_file:
            examiner_notes = Path(args.examiner_notes_file).read_text(encoding="utf-8")
        case_dir = Path(args.root) / "cases" / args.case_id
        if not case_dir.exists():
            raise FileNotFoundError(f"Case {args.case_id} does not exist under {case_dir.parent}. Ingest the case before report export.")
        package = export_case_report(case_dir, Path(args.output), args.examiner, examiner_notes)
        print(f"[REPORT] Evidence package exported to {package}")
        return

    if args.command == "validate":
        result = run_validation(Path(args.reference), Path(args.root))
        print(f"[VALIDATE] Reference: {result.reference_name}")
        print(f"[VALIDATE] Behavioral agreement: {result.behavioral_agreement:.1f}%")
        print(f"[VALIDATE] Vulnerability agreement: {result.vulnerability_agreement:.1f}%")
        print(f"[VALIDATE] Findings match: {result.findings_match}")
        print(f"[VALIDATE] Pass thresholds: {result.pass_thresholds}")
        return

    if args.command == "config-check":
        apply_runtime_provider_overrides(args)
        result = evaluate_config(args.provider, args.hosted_model or args.model)
        print(f"[CONFIG] Provider: {result['provider']}")
        print(f"[CONFIG] Ready: {result['ready']}")
        if result.get("effective_model"):
            print(f"[CONFIG] Effective model: {result['effective_model']}")
        if result.get("hosted_base_url"):
            print(f"[CONFIG] Hosted base URL: {result['hosted_base_url']}")
        if result.get("local_runtime_base_url"):
            print(f"[CONFIG] Local runtime base URL: {result['local_runtime_base_url']}")
        for note in result["notes"]:
            print(f"[CONFIG] Note: {note}")
        for issue in result["issues"]:
            print(f"[CONFIG] Issue: {issue}")
        return

    if args.command == "benchmark":
        apply_runtime_provider_overrides(args)
        profile = normalize_benchmark_profile(args.profile)
        benchmark_profile_settings(profile, replay_mode=args.replay_mode)
        summary = run_benchmark_suite(
            Path(args.validation_dir),
            Path(args.root),
            profile=profile,
            replay_dir=Path(args.replay_dir) if args.replay_dir else None,
            replay_mode=args.replay_mode,
        )
        print(f"[BENCHMARK] Fixtures: {summary['total_fixtures']}")
        print(f"[BENCHMARK] Passed: {summary['passed_fixtures']}")
        print(f"[BENCHMARK] Failed: {summary['failed_fixtures']}")
        print(f"[BENCHMARK] Pass rate: {summary['pass_rate']}%")
        print(f"[BENCHMARK] Profile: {summary['profile']}")
        print(f"[BENCHMARK] Total time: {summary['total_elapsed_seconds']}s")
        for result in summary["results"]:
            print(
                "[BENCHMARK] "
                f"{result['reference_name']}: "
                f"profile={result['profile']} "
                f"behavior={result['behavioral_agreement']:.1f}% "
                f"vulnerability={result['vulnerability_agreement']:.1f}% "
                f"findings_match={result['findings_match']} "
                f"pass={result['pass_thresholds']} "
                f"time={result['elapsed_seconds']}s"
            )
        if args.output_dir:
            artifacts = write_benchmark_artifacts(summary, Path(args.output_dir))
            print(f"[BENCHMARK] JSON artifact: {artifacts['json']}")
            print(f"[BENCHMARK] Markdown artifact: {artifacts['markdown']}")
            if args.sign_private_key and args.sign_public_key:
                signed = sign_artifact_bundle(
                    Path(args.output_dir),
                    Path(args.sign_private_key),
                    Path(args.sign_public_key),
                    args.signer_label,
                    Path(args.signing_certificate) if args.signing_certificate else None,
                    [Path(item) for item in args.certificate_chain],
                )
                verified = verify_artifact_bundle(Path(args.output_dir), Path(args.sign_public_key))
                print(f"[BENCHMARK] Artifact manifest: {signed['manifest']}")
                print(f"[BENCHMARK] Artifact signature: {signed['signature']}")
                print(f"[BENCHMARK] Artifact trust: {signed['trust']}")
                print(f"[BENCHMARK] Artifact verification pass: {verified['all_pass']}")
        if args.history_dir:
            snapshot = write_artifact_history_snapshot(summary, Path(args.history_dir), f"benchmark_{profile}_latest")
            print(f"[BENCHMARK] History snapshot latest: {snapshot['latest']}")
            print(f"[BENCHMARK] History snapshot dated: {snapshot['dated']}")
            history = write_history_summary(Path(args.history_dir), f"benchmark_{profile}_latest")
            print(f"[BENCHMARK] History summary JSON: {history['json']}")
            print(f"[BENCHMARK] History summary Markdown: {history['markdown']}")
            trend = write_history_trend_summary(Path(args.history_dir), f"benchmark_{profile}_latest")
            print(f"[BENCHMARK] Trend summary JSON: {trend['json']}")
            print(f"[BENCHMARK] Trend summary Markdown: {trend['markdown']}")
        return

    if args.command == "benchmark-replay":
        apply_runtime_provider_overrides(args)
        profile = normalize_benchmark_profile(args.profile)
        benchmark_profile_settings(profile, replay_mode="replay-only")
        summary = run_benchmark_suite(
            Path(args.validation_dir),
            Path(args.root),
            profile=profile,
            replay_dir=Path(args.replay_dir),
            replay_mode="replay-only",
        )
        print(f"[BENCHMARK-REPLAY] Fixtures: {summary['total_fixtures']}")
        print(f"[BENCHMARK-REPLAY] Passed: {summary['passed_fixtures']}")
        print(f"[BENCHMARK-REPLAY] Failed: {summary['failed_fixtures']}")
        print(f"[BENCHMARK-REPLAY] Pass rate: {summary['pass_rate']}%")
        print(f"[BENCHMARK-REPLAY] Profile: {summary['profile']}")
        for result in summary["results"]:
            print(
                "[BENCHMARK-REPLAY] "
                f"{result['reference_name']}: "
                f"behavior={result['behavioral_agreement']:.1f}% "
                f"vulnerability={result['vulnerability_agreement']:.1f}% "
                f"findings_match={result['findings_match']} "
                f"pass={result['pass_thresholds']}"
            )
        if args.output_dir:
            artifacts = write_benchmark_artifacts(summary, Path(args.output_dir))
            print(f"[BENCHMARK-REPLAY] JSON artifact: {artifacts['json']}")
            print(f"[BENCHMARK-REPLAY] Markdown artifact: {artifacts['markdown']}")
            if args.sign_private_key and args.sign_public_key:
                signed = sign_artifact_bundle(
                    Path(args.output_dir),
                    Path(args.sign_private_key),
                    Path(args.sign_public_key),
                    args.signer_label,
                    Path(args.signing_certificate) if args.signing_certificate else None,
                    [Path(item) for item in args.certificate_chain],
                )
                verified = verify_artifact_bundle(Path(args.output_dir), Path(args.sign_public_key))
                print(f"[BENCHMARK-REPLAY] Artifact manifest: {signed['manifest']}")
                print(f"[BENCHMARK-REPLAY] Artifact signature: {signed['signature']}")
                print(f"[BENCHMARK-REPLAY] Artifact trust: {signed['trust']}")
                print(f"[BENCHMARK-REPLAY] Artifact verification pass: {verified['all_pass']}")
        if args.history_dir:
            snapshot = write_artifact_history_snapshot(summary, Path(args.history_dir), f"benchmark_{profile}_replay_latest")
            print(f"[BENCHMARK-REPLAY] History snapshot latest: {snapshot['latest']}")
            print(f"[BENCHMARK-REPLAY] History snapshot dated: {snapshot['dated']}")
            history = write_history_summary(Path(args.history_dir), f"benchmark_{profile}_replay_latest")
            trend = write_history_trend_summary(Path(args.history_dir), f"benchmark_{profile}_replay_latest")
            print(f"[BENCHMARK-REPLAY] History summary JSON: {history['json']}")
            print(f"[BENCHMARK-REPLAY] Trend summary JSON: {trend['json']}")
        return

    if args.command == "benchmark-compare":
        apply_runtime_provider_overrides(args)
        baseline_profile = normalize_benchmark_profile(args.baseline_profile)
        candidate_profile = normalize_benchmark_profile(args.candidate_profile)
        benchmark_profile_settings(baseline_profile)
        benchmark_profile_settings(candidate_profile)
        baseline = run_benchmark_suite(
            Path(args.validation_dir),
            Path(args.root) / baseline_profile,
            profile=baseline_profile,
            replay_dir=(Path(args.replay_dir) / baseline_profile) if args.replay_dir else None,
            replay_mode=args.replay_mode,
        )
        candidate = run_benchmark_suite(
            Path(args.validation_dir),
            Path(args.root) / candidate_profile,
            profile=candidate_profile,
            replay_dir=(Path(args.replay_dir) / candidate_profile) if args.replay_dir else None,
            replay_mode=args.replay_mode,
        )
        comparison = apply_comparison_assessments(compare_benchmark_summaries(baseline, candidate))
        print(f"[BENCHMARK-COMPARE] Baseline: {comparison['baseline_profile']}")
        print(f"[BENCHMARK-COMPARE] Candidate: {comparison['candidate_profile']}")
        print(f"[BENCHMARK-COMPARE] References compared: {comparison['references_compared']}")
        print(f"[BENCHMARK-COMPARE] Drift count: {comparison['drift_count']}")
        print(f"[BENCHMARK-COMPARE] Drift free: {comparison['drift_free']}")
        policy = comparison.get("provider_drift_policy", {})
        if policy.get("policy_applied"):
            print(f"[BENCHMARK-COMPARE] Policy status: {policy['status']}")
            print(f"[BENCHMARK-COMPARE] Policy summary: {policy['summary']}")
        for item in comparison["comparisons"]:
            print(
                "[BENCHMARK-COMPARE] "
                f"{item['reference_name']}: "
                f"behavior_delta={item['behavioral_delta']} "
                f"vulnerability_delta={item['vulnerability_delta']} "
                f"findings_changed={item['findings_changed']} "
                f"threshold_changed={item['threshold_changed']} "
                f"drift={item['drift_detected']}"
            )
        if args.output_dir:
            artifacts = write_comparison_artifacts(comparison, Path(args.output_dir))
            print(f"[BENCHMARK-COMPARE] JSON artifact: {artifacts['json']}")
            print(f"[BENCHMARK-COMPARE] Markdown artifact: {artifacts['markdown']}")
            if args.sign_private_key and args.sign_public_key:
                signed = sign_artifact_bundle(
                    Path(args.output_dir),
                    Path(args.sign_private_key),
                    Path(args.sign_public_key),
                    args.signer_label,
                    Path(args.signing_certificate) if args.signing_certificate else None,
                    [Path(item) for item in args.certificate_chain],
                )
                verified = verify_artifact_bundle(Path(args.output_dir), Path(args.sign_public_key))
                print(f"[BENCHMARK-COMPARE] Artifact manifest: {signed['manifest']}")
                print(f"[BENCHMARK-COMPARE] Artifact signature: {signed['signature']}")
                print(f"[BENCHMARK-COMPARE] Artifact trust: {signed['trust']}")
                print(f"[BENCHMARK-COMPARE] Artifact verification pass: {verified['all_pass']}")
        if args.history_dir:
            snapshot = write_artifact_history_snapshot(
                comparison,
                Path(args.history_dir),
                f"benchmark_compare_{baseline_profile}_vs_{candidate_profile}_latest",
            )
            print(f"[BENCHMARK-COMPARE] History snapshot latest: {snapshot['latest']}")
            print(f"[BENCHMARK-COMPARE] History snapshot dated: {snapshot['dated']}")
            history = write_history_summary(
                Path(args.history_dir),
                f"benchmark_compare_{baseline_profile}_vs_{candidate_profile}_latest",
            )
            print(f"[BENCHMARK-COMPARE] History summary JSON: {history['json']}")
            print(f"[BENCHMARK-COMPARE] History summary Markdown: {history['markdown']}")
            trend = write_history_trend_summary(
                Path(args.history_dir),
                f"benchmark_compare_{baseline_profile}_vs_{candidate_profile}_latest",
            )
            print(f"[BENCHMARK-COMPARE] Trend summary JSON: {trend['json']}")
            print(f"[BENCHMARK-COMPARE] Trend summary Markdown: {trend['markdown']}")
        return

    if args.command == "benchmark-history":
        snapshots = collect_history_snapshots(Path(args.history_dir), args.prefix)
        summary = write_history_summary(Path(args.history_dir), args.prefix)
        print(f"[BENCHMARK-HISTORY] Prefix: {args.prefix}")
        print(f"[BENCHMARK-HISTORY] Snapshots: {len(snapshots)}")
        print(f"[BENCHMARK-HISTORY] JSON summary: {summary['json']}")
        print(f"[BENCHMARK-HISTORY] Markdown summary: {summary['markdown']}")
        return

    if args.command == "benchmark-trend":
        snapshots = collect_history_snapshots(Path(args.history_dir), args.prefix)
        summary = build_history_trend_summary(args.prefix, snapshots)
        artifacts = write_history_trend_summary(Path(args.history_dir), args.prefix)
        print(f"[BENCHMARK-TREND] Prefix: {args.prefix}")
        print(f"[BENCHMARK-TREND] Series type: {summary['series_type']}")
        print(f"[BENCHMARK-TREND] Snapshots: {summary['snapshot_count']}")
        print(f"[BENCHMARK-TREND] JSON summary: {artifacts['json']}")
        print(f"[BENCHMARK-TREND] Markdown summary: {artifacts['markdown']}")
        return

    if args.command == "verify-package":
        checks = verify_evidence_package(Path(args.package))
        for key, value in checks.items():
            print(f"[VERIFY] {key}: {value}")
        return

    if args.command == "sign-package":
        path = sign_manifest(
            Path(args.package),
            Path(args.private_key),
            Path(args.public_key) if args.public_key else None,
            args.signer_label,
            [Path(item) for item in args.certificate_chain],
            Path(args.signing_certificate) if args.signing_certificate else None,
        )
        print(f"[SIGN] Manifest signature written to {path}")
        return

    if args.command == "verify-signature":
        checks = verify_manifest_signature(Path(args.package), Path(args.public_key))
        for key, value in checks.items():
            print(f"[VERIFY-SIGNATURE] {key}: {value}")
        if args.ca_file:
            cert_checks = verify_signing_certificate(
                Path(args.package),
                Path(args.ca_file),
                Path(args.crl_file) if args.crl_file else None,
            )
            for key, value in cert_checks.items():
                print(f"[VERIFY-CERTIFICATE] {key}: {value}")
        return

    if args.command == "version":
        print(__version__)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError) as error:
        raise SystemExit(f"[ERROR] {error}")
