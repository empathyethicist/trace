from __future__ import annotations

import argparse
from pathlib import Path

from trace import __version__
from trace.classify import classify_case
from trace.ingest import ingest_case
from trace.irr import compute_irr, import_second_coder
from trace.report import (
    export_case_report,
    sign_manifest,
    verify_evidence_package,
    verify_manifest_signature,
    verify_signing_certificate,
)
from trace.validation import (
    apply_comparison_assessments,
    benchmark_profile_settings,
    build_history_trend_summary,
    compare_benchmark_summaries,
    collect_history_snapshots,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trace")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest")
    ingest.add_argument("--input", required=True)
    ingest.add_argument("--format", required=True, choices=["json", "csv", "text", "plain", "court", "axiom", "ufed"])
    ingest.add_argument("--case-id", required=True)
    ingest.add_argument("--examiner", required=True)
    ingest.add_argument("--root", default=str(DEFAULT_ROOT))

    classify = sub.add_parser("classify")
    classify.add_argument("--case-id", required=True)
    classify.add_argument("--examiner", default="trace")
    classify.add_argument("--root", default=str(DEFAULT_ROOT))
    classify.add_argument("--manual", action="store_true")
    classify.add_argument("--provider", default="heuristic", choices=["heuristic", "mock", "ollama", "openrouter", "none"])
    classify.add_argument("--model", default="trace-heuristic-v1")
    classify.add_argument("--temperature", type=float, default=0.0)
    classify.add_argument("--window-size", type=int, default=20)
    classify.add_argument("--review-mode", default="auto", choices=["auto", "flag-low-confidence", "interactive"])

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

    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("--validation-dir", default=str(Path.cwd() / "validation"))
    benchmark.add_argument("--root", default=str(DEFAULT_ROOT))
    benchmark.add_argument("--profile", default="heuristic", choices=["heuristic", "hosted", "live-hosted"])
    benchmark.add_argument("--output-dir")
    benchmark.add_argument("--history-dir")
    benchmark.add_argument("--sign-private-key")
    benchmark.add_argument("--sign-public-key")
    benchmark.add_argument("--signer-label", default="TRACE benchmark signer")
    benchmark.add_argument("--signing-certificate")
    benchmark.add_argument("--certificate-chain", action="append", default=[])

    compare = sub.add_parser("benchmark-compare")
    compare.add_argument("--validation-dir", default=str(Path.cwd() / "validation"))
    compare.add_argument("--root", default=str(DEFAULT_ROOT))
    compare.add_argument("--baseline-profile", default="heuristic", choices=["heuristic", "hosted", "live-hosted"])
    compare.add_argument("--candidate-profile", default="hosted", choices=["heuristic", "hosted", "live-hosted"])
    compare.add_argument("--output-dir")
    compare.add_argument("--history-dir")
    compare.add_argument("--sign-private-key")
    compare.add_argument("--sign-public-key")
    compare.add_argument("--signer-label", default="TRACE benchmark signer")
    compare.add_argument("--signing-certificate")
    compare.add_argument("--certificate-chain", action="append", default=[])

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

    if args.command == "classify":
        model = args.model
        if not args.manual and args.provider == "openrouter" and model == "trace-heuristic-v1":
            model = "openrouter/free"
        result = classify_case(
            Path(args.root) / "cases" / args.case_id,
            args.examiner,
            mode="manual" if args.manual else "heuristic",
            provider="none" if args.manual else args.provider,
            model="manual-human-review" if args.manual else model,
            temperature=args.temperature,
            window_size=args.window_size,
            review_mode=args.review_mode,
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
        package = export_case_report(Path(args.root) / "cases" / args.case_id, Path(args.output), args.examiner, examiner_notes)
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

    if args.command == "benchmark":
        benchmark_profile_settings(args.profile)
        summary = run_benchmark_suite(Path(args.validation_dir), Path(args.root), profile=args.profile)
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
            snapshot = write_artifact_history_snapshot(summary, Path(args.history_dir), f"benchmark_{args.profile}_latest")
            print(f"[BENCHMARK] History snapshot latest: {snapshot['latest']}")
            print(f"[BENCHMARK] History snapshot dated: {snapshot['dated']}")
            history = write_history_summary(Path(args.history_dir), f"benchmark_{args.profile}_latest")
            print(f"[BENCHMARK] History summary JSON: {history['json']}")
            print(f"[BENCHMARK] History summary Markdown: {history['markdown']}")
            trend = write_history_trend_summary(Path(args.history_dir), f"benchmark_{args.profile}_latest")
            print(f"[BENCHMARK] Trend summary JSON: {trend['json']}")
            print(f"[BENCHMARK] Trend summary Markdown: {trend['markdown']}")
        return

    if args.command == "benchmark-compare":
        benchmark_profile_settings(args.baseline_profile)
        benchmark_profile_settings(args.candidate_profile)
        baseline = run_benchmark_suite(Path(args.validation_dir), Path(args.root) / args.baseline_profile, profile=args.baseline_profile)
        candidate = run_benchmark_suite(Path(args.validation_dir), Path(args.root) / args.candidate_profile, profile=args.candidate_profile)
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
                f"benchmark_compare_{args.baseline_profile}_vs_{args.candidate_profile}_latest",
            )
            print(f"[BENCHMARK-COMPARE] History snapshot latest: {snapshot['latest']}")
            print(f"[BENCHMARK-COMPARE] History snapshot dated: {snapshot['dated']}")
            history = write_history_summary(
                Path(args.history_dir),
                f"benchmark_compare_{args.baseline_profile}_vs_{args.candidate_profile}_latest",
            )
            print(f"[BENCHMARK-COMPARE] History summary JSON: {history['json']}")
            print(f"[BENCHMARK-COMPARE] History summary Markdown: {history['markdown']}")
            trend = write_history_trend_summary(
                Path(args.history_dir),
                f"benchmark_compare_{args.baseline_profile}_vs_{args.candidate_profile}_latest",
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
    main()
