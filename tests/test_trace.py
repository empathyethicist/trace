from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import subprocess

from trace.classify import classify_case
from trace.ingest import (
    ingest_case,
    parse_axiom_json_records,
    parse_court_transcript_records,
    parse_text_records,
    parse_ufed_xml_records,
)
from trace.irr import cohen_kappa, compute_irr, import_second_coder, krippendorff_alpha_nominal, krippendorff_alpha_ordinal
from trace.report import compute_findings, export_case_report, verify_evidence_package
from trace.report import sign_manifest, verify_manifest_signature
from trace.storage import read_json
from trace.validation import run_validation


FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "companion_incident.json"
BENIGN_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_benign_case.json"
LONG_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_long_case.json"
PARSER_FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "validation" / "parsers"


class TraceTests(unittest.TestCase):
    def test_parse_text_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("[00:00] user: hello\n[00:01] system: hi\n", encoding="utf-8")
            records = parse_text_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "user")

    def test_parse_additional_formats(self) -> None:
        court = PARSER_FIXTURE_ROOT / "court_transcript.txt"
        axiom = PARSER_FIXTURE_ROOT / "axiom_messages.json"
        ufed = PARSER_FIXTURE_ROOT / "ufed_messages.xml"
        self.assertEqual(len(parse_court_transcript_records(court)), 4)
        self.assertEqual(len(parse_axiom_json_records(axiom)), 4)
        self.assertEqual(len(parse_ufed_xml_records(ufed)), 4)
        self.assertEqual(parse_court_transcript_records(court)[1]["speaker"], "system")
        self.assertEqual(parse_axiom_json_records(axiom)[2]["speaker"], "user")
        self.assertEqual(parse_ufed_xml_records(ufed)[3]["speaker"], "system")

    def test_ingest_supported_parser_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cases"
            court = ingest_case(PARSER_FIXTURE_ROOT / "court_transcript.txt", "COURT-1", "tester", "court", root)
            axiom = ingest_case(PARSER_FIXTURE_ROOT / "axiom_messages.json", "AXIOM-1", "tester", "axiom", root)
            ufed = ingest_case(PARSER_FIXTURE_ROOT / "ufed_messages.xml", "UFED-1", "tester", "ufed", root)
            self.assertEqual(court.transcript_count, 4)
            self.assertEqual(axiom.transcript_count, 4)
            self.assertEqual(ufed.transcript_count, 4)

    def test_ingest_classify_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = ingest_case(FIXTURE, "CASE-1", "tester", "json", root / "cases")
            self.assertEqual(result.transcript_count, 8)
            classified = classify_case(root / "cases" / "CASE-1", "tester")
            self.assertEqual(classified.message_count, 8)
            findings = compute_findings(read_json(root / "cases" / "CASE-1" / "classified_transcript.json")["transcript"])
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 75)
            package = export_case_report(root / "cases" / "CASE-1", root / "out", "tester")
            self.assertTrue((package / "manifest.json").exists())
            self.assertTrue((package / "configuration" / "prompt_templates" / "sbc_v1.0.txt").exists())
            self.assertTrue((package / "forensic_report.pdf").exists())
            self.assertTrue((package / "override_summary.json").exists())
            self.assertTrue(verify_evidence_package(package)["all_pass"])

    def test_manifest_sign_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-SIGN", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-SIGN", "tester")
            package = export_case_report(root / "cases" / "CASE-SIGN", root / "out", "tester")
            private_key = root / "trace_private.pem"
            public_key = root / "trace_public.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(private_key), "-pkeyopt", "rsa_keygen_bits:2048"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["openssl", "rsa", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True,
                capture_output=True,
                text=True,
            )
            sign_manifest(package, private_key, public_key, "TRACE test signer")
            verification = verify_manifest_signature(package, public_key)
            self.assertTrue(verification["all_pass"])
            trust_metadata = read_json(package / "trust_metadata.json")
            self.assertEqual(trust_metadata["signer_label"], "TRACE test signer")
            self.assertEqual(trust_metadata["public_key_path"], "trace_public.pem")

    def test_mock_provider_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-MOCK", "tester", "json", root / "cases")
            result = classify_case(
                root / "cases" / "CASE-MOCK",
                "tester",
                provider="mock",
                model="mock-model",
                window_size=4,
                review_mode="flag-low-confidence",
            )
            self.assertEqual(result.message_count, 8)
            classified = read_json(root / "cases" / "CASE-MOCK" / "classified_transcript.json")
            self.assertEqual(classified["llm_provider"], "mock")
            self.assertEqual(classified["window_size"], 4)

    def test_irr_metrics(self) -> None:
        self.assertAlmostEqual(cohen_kappa(["a", "a", "b"], ["a", "a", "b"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_nominal(["x", "y"], ["x", "y"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_ordinal([0, 1, 4], [0, 1, 4]), 1.0)

    def test_import_and_compute_irr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-2", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-2", "tester")
            coder2 = root / "coder2.json"
            coder2.write_text((root / "cases" / "CASE-2" / "classified_transcript.json").read_text(encoding="utf-8"), encoding="utf-8")
            import_second_coder(root / "cases" / "CASE-2", coder2)
            stats = compute_irr(root / "cases" / "CASE-2")
            self.assertEqual(stats["krippendorff_alpha_behavioral"], 1.0)

    def test_validation_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_validation(FIXTURE, Path(tmp))
            self.assertTrue(result.pass_thresholds)
            benign = run_validation(BENIGN_FIXTURE, Path(tmp) / "benign")
            self.assertTrue(benign.pass_thresholds)

    def test_long_transcript_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(LONG_FIXTURE, "LONG-CASE", "tester", "json", root / "cases")
            classify_case(root / "cases" / "LONG-CASE", "tester", window_size=8)
            package = export_case_report(root / "cases" / "LONG-CASE", root / "out", "tester")
            report_md = (package / "forensic_report.md").read_text(encoding="utf-8")
            self.assertIn("Inappropriate Response Rate", report_md)
            self.assertIn("Overridden Classifications", report_md)
            findings = read_json(package / "correlation_analysis.json")
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 80.0)


if __name__ == "__main__":
    unittest.main()
