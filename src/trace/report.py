from __future__ import annotations

import csv
import hashlib
import json
import subprocess
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


def compute_override_summary(transcript: list[dict]) -> dict:
    overridden = []
    flagged = []
    accepted = 0
    for message in transcript:
        classification = message.get("classification") or {}
        decision = classification.get("decision", "accepted")
        if decision == "overridden":
            overridden.append(
                {
                    "message_id": message["id"],
                    "speaker": message["speaker"],
                    "decision": decision,
                    "override_rationale": classification.get("override_rationale", ""),
                    "behavioral_category": classification.get("behavioral_category"),
                    "behavioral_subcategory": classification.get("behavioral_subcategory"),
                    "ai_role": classification.get("ai_role"),
                    "vulnerability_level": classification.get("vulnerability_level"),
                }
            )
        elif decision == "flagged":
            flagged.append(
                {
                    "message_id": message["id"],
                    "speaker": message["speaker"],
                    "requires_review": classification.get("requires_review", False),
                }
            )
        else:
            accepted += 1
    return {
        "accepted_count": accepted,
        "flagged_count": len(flagged),
        "overridden_count": len(overridden),
        "flagged_messages": flagged,
        "overridden_messages": overridden,
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


def hash_package_contents(package_dir: Path) -> str:
    digest = hashlib.sha256()
    excluded = {"verification.json", "manifest.sig"}
    for child in sorted(p for p in package_dir.rglob("*") if p.is_file() and p.name not in excluded):
        digest.update(child.relative_to(package_dir).as_posix().encode("utf-8"))
        if child.name == "manifest.json":
            manifest = read_json(child)
            manifest["package_hash_sha256"] = ""
            digest.update((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        else:
            digest.update(child.read_bytes())
    return digest.hexdigest()


def write_report_markdown(case_id: str, findings: dict, override_summary: dict) -> str:
    lines = [
        f"# TRACE Forensic Report\n\n"
        f"- Case ID: `{case_id}`\n"
        f"- Inappropriate Response Rate: `{findings['inappropriate_response_rate']}%`\n"
        f"- Crisis Failure Rate: `{findings['crisis_failure_rate']}%`\n"
        f"- Pattern Systematic: `{findings['pattern_distribution']['systematic']}`\n"
        f"- Concentration Index: `{findings['pattern_distribution']['concentration_index']}`\n"
        f"- Accepted Classifications: `{override_summary['accepted_count']}`\n"
        f"- Flagged Classifications: `{override_summary['flagged_count']}`\n"
        f"- Overridden Classifications: `{override_summary['overridden_count']}`\n"
    ]
    if override_summary["overridden_messages"]:
        lines.append("\n## Override Summary\n\n")
        for item in override_summary["overridden_messages"]:
            lines.append(
                f"- Message `{item['message_id']}` ({item['speaker']}): "
                f"`{item['override_rationale'] or 'No rationale provided'}`\n"
            )
    return "".join(lines)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_pdf_text(line: str, width: int = 88) -> list[str]:
    words = line.split()
    if not words:
        return [""]
    wrapped: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            wrapped.append(current)
            current = word
    wrapped.append(current)
    return wrapped


def write_report_pdf(path: Path, case_id: str, findings: dict, override_summary: dict) -> None:
    report_lines = [
        "TRACE Forensic Report",
        f"Case ID: {case_id}",
        f"Inappropriate Response Rate: {findings['inappropriate_response_rate']}%",
        f"Crisis Failure Rate: {findings['crisis_failure_rate']}%",
        f"Pattern Systematic: {findings['pattern_distribution']['systematic']}",
        f"Concentration Index: {findings['pattern_distribution']['concentration_index']}",
        f"Accepted Classifications: {override_summary['accepted_count']}",
        f"Flagged Classifications: {override_summary['flagged_count']}",
        f"Overridden Classifications: {override_summary['overridden_count']}",
    ]
    for item in override_summary["overridden_messages"]:
        report_lines.append(
            f"Override #{item['message_id']} ({item['speaker']}): {item['override_rationale'] or 'No rationale provided'}"
        )
    lines = ["BT", "/F1 18 Tf 72 760 Td"]
    first_line = True
    for index, line in enumerate(report_lines):
        font_size = 18 if index == 0 else 12
        wrapped = _wrap_pdf_text(line, width=72 if font_size == 18 else 92)
        for wrapped_line in wrapped:
            if first_line:
                lines.append(f"({ _pdf_escape(wrapped_line) }) Tj")
                first_line = False
            else:
                lines.append(f"/F1 {font_size} Tf 0 -18 Td ({_pdf_escape(wrapped_line)}) Tj")
        if index == 0:
            lines.append("/F1 12 Tf 0 -10 Td () Tj")
    lines.append("ET")
    stream = "\n".join(lines).encode("latin-1", errors="replace")
    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(f"5 0 obj << /Length {len(stream)} >> stream\n".encode("ascii") + stream + b"\nendstream endobj\n")
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii"))
    path.write_bytes(bytes(pdf))


def verify_evidence_package(package_dir: Path) -> dict:
    manifest = read_json(package_dir / "manifest.json")
    checks = {
        "source_hash_present": bool(manifest.get("source_hash_sha256")),
        "classified_hash_matches": manifest.get("classified_hash_sha256") == hash_path(package_dir / "classified_transcript.json"),
    }
    checks["package_hash_matches"] = manifest.get("package_hash_sha256") == hash_package_contents(package_dir)
    checks["all_pass"] = all(checks.values())
    return checks


def verify_manifest_signature(package_dir: Path, public_key_path: Path) -> dict:
    signature_path = package_dir / "manifest.sig"
    trust_metadata_path = package_dir / "trust_metadata.json"
    result = {
        "signature_present": signature_path.exists(),
        "public_key_present": public_key_path.exists(),
        "trust_metadata_present": trust_metadata_path.exists(),
        "signature_valid": False,
    }
    if not result["signature_present"] or not result["public_key_present"]:
        result["all_pass"] = False
        return result
    completed = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key_path),
            "-signature",
            str(signature_path),
            str(package_dir / "manifest.json"),
        ],
        capture_output=True,
        text=True,
    )
    result["signature_valid"] = completed.returncode == 0
    result["stdout"] = completed.stdout.strip()
    result["stderr"] = completed.stderr.strip()
    if trust_metadata_path.exists():
        trust = read_json(trust_metadata_path)
        result["trust_public_key_match"] = trust.get("public_key_sha256") == hash_path(public_key_path)
        result["signer_label"] = trust.get("signer_label")
    else:
        result["trust_public_key_match"] = False
    result["all_pass"] = result["signature_present"] and result["public_key_present"] and result["signature_valid"]
    if result["trust_metadata_present"]:
        result["all_pass"] = result["all_pass"] and result["trust_public_key_match"]
    return result


def build_trust_metadata(
    package_dir: Path,
    public_key_path: Path | None = None,
    signer_label: str | None = None,
    certificate_chain_paths: list[Path] | None = None,
) -> dict:
    metadata = {
        "signature_algorithm": "RSA-SHA256",
        "signer_label": signer_label or "unspecified",
        "manifest_path": "manifest.json",
        "signature_path": "manifest.sig",
        "public_key_path": public_key_path.name if public_key_path else None,
        "public_key_sha256": hash_path(public_key_path) if public_key_path and public_key_path.exists() else None,
        "certificate_chain": [],
    }
    for chain_path in certificate_chain_paths or []:
        metadata["certificate_chain"].append(
            {
                "path": chain_path.name,
                "sha256": hash_path(chain_path),
            }
        )
    write_json(package_dir / "trust_metadata.json", metadata)
    return metadata


def sign_manifest(
    package_dir: Path,
    private_key_path: Path,
    public_key_path: Path | None = None,
    signer_label: str | None = None,
    certificate_chain_paths: list[Path] | None = None,
) -> Path:
    signature_path = package_dir / "manifest.sig"
    subprocess.run(
        [
            "openssl", "dgst", "-sha256", "-sign", str(private_key_path),
            "-out", str(signature_path), str(package_dir / "manifest.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    build_trust_metadata(package_dir, public_key_path, signer_label, certificate_chain_paths)
    return signature_path


def export_case_report(case_dir: Path, output_root: Path, examiner_id: str) -> Path:
    source = read_json(case_dir / "source_transcript.json")
    classified = read_json(case_dir / "classified_transcript.json")
    findings = compute_findings(classified["transcript"])
    override_summary = compute_override_summary(classified["transcript"])
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
        write_report_markdown(source["case_id"], findings, override_summary), encoding="utf-8"
    )
    write_report_pdf(package_dir / "forensic_report.pdf", source["case_id"], findings, override_summary)
    write_json(
        package_dir / "forensic_report.json",
        {
            "case_id": source["case_id"],
            "findings": findings,
            "override_summary": override_summary,
            "generated_at": utc_now_iso(),
        },
    )
    write_json(package_dir / "override_summary.json", override_summary)
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
    manifest["package_hash_sha256"] = hash_package_contents(package_dir)
    write_json(package_dir / "manifest.json", manifest)
    write_json(package_dir / "verification.json", verify_evidence_package(package_dir))

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
