from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from trace.classify import classify_case
from trace.ingest import ingest_case
from trace.report import compute_findings
from trace.storage import read_json


@dataclass
class ValidationResult:
    behavioral_agreement: float
    vulnerability_agreement: float
    findings_match: bool
    pass_thresholds: bool


def run_validation(reference_path: Path, working_root: Path) -> ValidationResult:
    reference = read_json(reference_path)
    case_id = reference["case_id"]
    case_root = working_root / "cases"
    ingest_case(reference_path, case_id, "validator", "json", case_root)
    classify_case(case_root / case_id, "validator")
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
    return ValidationResult(
        behavioral_agreement=behavioral_agreement,
        vulnerability_agreement=vulnerability_agreement,
        findings_match=findings_match,
        pass_thresholds=pass_thresholds,
    )
