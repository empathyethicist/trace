from __future__ import annotations

import argparse
from pathlib import Path

from trace import __version__
from trace.classify import classify_case
from trace.ingest import ingest_case
from trace.irr import compute_irr, import_second_coder
from trace.report import export_case_report, sign_manifest, verify_evidence_package, verify_manifest_signature
from trace.validation import run_validation


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
    report.add_argument("--root", default=str(DEFAULT_ROOT))

    validate = sub.add_parser("validate")
    validate.add_argument("--reference", required=True)
    validate.add_argument("--root", default=str(DEFAULT_ROOT))

    verify = sub.add_parser("verify-package")
    verify.add_argument("--package", required=True)

    sign = sub.add_parser("sign-package")
    sign.add_argument("--package", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--public-key")
    sign.add_argument("--signer-label")
    sign.add_argument("--certificate-chain", action="append", default=[])

    verify_sig = sub.add_parser("verify-signature")
    verify_sig.add_argument("--package", required=True)
    verify_sig.add_argument("--public-key", required=True)

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
        package = export_case_report(Path(args.root) / "cases" / args.case_id, Path(args.output), args.examiner)
        print(f"[REPORT] Evidence package exported to {package}")
        return

    if args.command == "validate":
        result = run_validation(Path(args.reference), Path(args.root))
        print(f"[VALIDATE] Behavioral agreement: {result.behavioral_agreement:.1f}%")
        print(f"[VALIDATE] Vulnerability agreement: {result.vulnerability_agreement:.1f}%")
        print(f"[VALIDATE] Findings match: {result.findings_match}")
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
        )
        print(f"[SIGN] Manifest signature written to {path}")
        return

    if args.command == "verify-signature":
        checks = verify_manifest_signature(Path(args.package), Path(args.public_key))
        for key, value in checks.items():
            print(f"[VERIFY-SIGNATURE] {key}: {value}")
        return

    if args.command == "version":
        print(__version__)


if __name__ == "__main__":
    main()
