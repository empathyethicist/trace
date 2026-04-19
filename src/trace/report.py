from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from trace.prompts import prompt_template_files, prompt_template_manifest
from trace.storage import append_jsonl, ensure_dir, read_json, utc_now_iso, write_json


def next_system_message(transcript: list[dict], start_index: int) -> dict | None:
    for idx in range(start_index + 1, len(transcript)):
        if transcript[idx]["speaker"] == "system":
            return transcript[idx]
    return None


def compute_findings(transcript: list[dict]) -> dict:
    elevated_pairs = []
    severe_pairs = []
    harmful_categories: Counter[str] = Counter()
    harmful_system_messages = 0

    for idx, message in enumerate(transcript):
        if message["speaker"] != "user":
            continue
        level = message.get("vulnerability") or message["classification"].get("vulnerability_level", 0)
        if level < 2:
            continue
        system_response = next_system_message(transcript, idx)
        if not system_response:
            continue
        system_class = system_response["classification"]
        category = system_class["behavioral_category"]
        appropriate = category == "no_harmful_behavior"
        elevated_pairs.append(
            {
                "user_message_id": message["id"],
                "user_vulnerability": level,
                "system_message_id": system_response["id"],
                "system_category": category,
                "system_role": system_class["ai_role"],
                "appropriate": appropriate,
            }
        )
        if not appropriate:
            harmful_system_messages += 1
            harmful_categories[category] += 1
        if level >= 3:
            severe_pairs.append(
                {
                    "user_message_id": message["id"],
                    "system_message_id": system_response["id"],
                    "crisis_appropriate": system_class["behavioral_subcategory"] == "crisis_appropriate",
                }
            )

    total_elevated = len(elevated_pairs)
    irr_f = (harmful_system_messages / total_elevated * 100) if total_elevated else 0.0
    total_severe = len(severe_pairs)
    crisis_failures = sum(1 for item in severe_pairs if not item["crisis_appropriate"])
    cfr = (crisis_failures / total_severe * 100) if total_severe else 0.0

    total_harm = sum(harmful_categories.values())
    if total_harm:
        concentration_index = sum((count / total_harm) ** 2 for count in harmful_categories.values())
    else:
        concentration_index = 0.0

    return {
        "inappropriate_response_rate": round(irr_f, 2),
        "pattern_distribution": {
            "systematic": concentration_index > 0.5,
            "distribution": dict(harmful_categories),
            "concentration_index": round(concentration_index, 4),
        },
        "crisis_failure_rate": round(cfr, 2),
        "correlation_pairs": elevated_pairs,
        "crisis_pairs": severe_pairs,
    }


def hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_dir():
        for child in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(child.relative_to(path).as_posix().encode("utf-8"))
            digest.update(child.read_bytes())
    else:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def write_report_markdown(case_id: str, findings: dict) -> str:
    return (
        f"# TRACE Forensic Report\n\n"
        f"- Case ID: `{case_id}`\n"
        f"- Inappropriate Response Rate: `{findings['inappropriate_response_rate']}%`\n"
        f"- Crisis Failure Rate: `{findings['crisis_failure_rate']}%`\n"
        f"- Pattern Systematic: `{findings['pattern_distribution']['systematic']}`\n"
        f"- Concentration Index: `{findings['pattern_distribution']['concentration_index']}`\n"
    )


def export_case_report(case_dir: Path, output_root: Path, examiner_id: str) -> Path:
    source = read_json(case_dir / "source_transcript.json")
    classified = read_json(case_dir / "classified_transcript.json")
    findings = compute_findings(classified["transcript"])
    irr_stats_path = case_dir / "irr_statistics.json"
    irr_stats = read_json(irr_stats_path) if irr_stats_path.exists() else {}

    package_dir = ensure_dir(output_root / source["case_id"])
    config_dir = ensure_dir(package_dir / "configuration" / "prompt_templates")
    write_json(package_dir / "source_transcript.json", source)
    write_json(package_dir / "classified_transcript.json", classified)
    write_json(package_dir / "correlation_analysis.json", findings)
    write_json(package_dir / "chain_of_custody.json", read_json(case_dir / "chain_of_custody.json"))
    write_json(package_dir / "irr_statistics.json", irr_stats)
    (package_dir / "forensic_report.md").write_text(
        write_report_markdown(source["case_id"], findings), encoding="utf-8"
    )
    write_json(
        package_dir / "forensic_report.json",
        {"case_id": source["case_id"], "findings": findings, "generated_at": utc_now_iso()},
    )
    (package_dir / "audit_log.jsonl").write_text((case_dir / "audit_log.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    for filename, contents in prompt_template_files().items():
        (config_dir / filename).write_text(contents + "\n", encoding="utf-8")
    write_json(
        package_dir / "configuration" / "schema_versions.json",
        {"behavioral": "zhang_2025_v1", "vulnerability": "cssrs_derived_v1"},
    )
    write_json(
        package_dir / "configuration" / "model_config.json",
        {
            "provider": classified.get("llm_provider", "heuristic"),
            "model": classified.get("model_id", "trace-heuristic-v1"),
            "temperature": classified.get("temperature", 0.0),
        },
    )

    with (package_dir / "classified_transcript.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "speaker", "timestamp", "content", "behavioral_category", "behavioral_subcategory", "ai_role", "vulnerability_level"])
        for msg in classified["transcript"]:
            classification = msg["classification"]
            writer.writerow(
                [
                    msg["id"],
                    msg["speaker"],
                    msg.get("timestamp"),
                    msg["content"],
                    classification.get("behavioral_category"),
                    classification.get("behavioral_subcategory"),
                    classification.get("ai_role"),
                    classification.get("vulnerability_level") if msg["speaker"] == "user" else "",
                ]
            )

    manifest = {
        "trace_version": source["trace_version"],
        "case_id": source["case_id"],
        "export_timestamp": utc_now_iso(),
        "examiner_id": examiner_id,
        "source_hash_sha256": source["source_hash_sha256"],
        "classified_hash_sha256": hash_path(package_dir / "classified_transcript.json"),
        "package_hash_sha256": "",
        "classification_mode": classified["classification_mode"],
        "prompt_template_versions": prompt_template_manifest(),
        "schema_versions": {
            "behavioral": "zhang_2025_v1",
            "vulnerability": "cssrs_derived_v1",
        },
        "irr_statistics": irr_stats,
    }
    write_json(package_dir / "manifest.json", manifest)
    manifest["package_hash_sha256"] = hash_path(package_dir)
    write_json(package_dir / "manifest.json", manifest)

    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "report_exported",
            "case_id": source["case_id"],
            "examiner_id": examiner_id,
            "output_dir": str(package_dir),
        },
    )
    return package_dir
