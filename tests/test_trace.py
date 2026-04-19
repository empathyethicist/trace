from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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
from trace.storage import read_json
from trace.validation import run_validation


FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "companion_incident.json"
BENIGN_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_benign_case.json"


class TraceTests(unittest.TestCase):
    def test_parse_text_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("[00:00] user: hello\n[00:01] system: hi\n", encoding="utf-8")
            records = parse_text_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "user")

    def test_parse_additional_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            court = root / "court.txt"
            court.write_text("[10:00] User: Hello\n[10:01] AI: Hi there\n", encoding="utf-8")
            self.assertEqual(len(parse_court_transcript_records(court)), 2)
            axiom = root / "axiom.json"
            axiom.write_text('{"messages":[{"speaker":"user","timestamp":"t1","content":"hi"},{"speaker":"system","timestamp":"t2","content":"hello"}]}', encoding="utf-8")
            self.assertEqual(len(parse_axiom_json_records(axiom)), 2)
            ufed = root / "ufed.xml"
            ufed.write_text('<root><message speaker="user" timestamp="t1" content="hi"/><message speaker="system" timestamp="t2" content="hello"/></root>', encoding="utf-8")
            self.assertEqual(len(parse_ufed_xml_records(ufed)), 2)

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
            self.assertTrue(verify_evidence_package(package)["all_pass"])

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


if __name__ == "__main__":
    unittest.main()
