from __future__ import annotations

import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from trace_forensics.storage import append_jsonl, ensure_dir, utc_now_iso, write_json


PLAIN_TEXT_PATTERN = re.compile(
    r"^\s*(?:\[(?P<timestamp>[^\]]+)\]\s*)?(?P<speaker>system|user)\s*:\s*(?P<content>.+?)\s*$",
    re.IGNORECASE,
)
COURT_TRANSCRIPT_PATTERN = re.compile(
    r"^\s*(?:\[(?P<timestamp>[^\]]+)\]\s*)?(?P<speaker>User|System|AI|Assistant|Human)\s*:\s*(?P<content>.+?)\s*$",
    re.IGNORECASE,
)


@dataclass
class IngestResult:
    case_dir: Path
    normalized_path: Path
    source_hash: str
    transcript_count: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_json_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "transcript" in data:
        data = data["transcript"]
    if not isinstance(data, list):
        raise ValueError("JSON transcript must be a list of messages or an object with transcript")
    parsed = []
    for idx, item in enumerate(data, start=1):
        speaker = str(item.get("speaker", "")).strip().lower()
        parsed.append(
            {
                "id": idx,
                "speaker": normalize_speaker(speaker),
                "timestamp": item.get("timestamp"),
                "content": str(item.get("content", "")).strip(),
                "classification": None,
                "vulnerability": None,
            }
        )
    return parsed


def parse_csv_records(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            rows.append(
                {
                    "id": idx,
                    "speaker": normalize_speaker(str(row.get("speaker", ""))),
                    "timestamp": row.get("timestamp") or None,
                    "content": str(row.get("content", "")).strip(),
                    "classification": None,
                    "vulnerability": None,
                }
            )
    return rows


def parse_text_records(path: Path) -> list[dict]:
    rows = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        match = PLAIN_TEXT_PATTERN.match(line)
        if not match:
            raise ValueError(f"Could not parse line {idx}: {line}")
        rows.append(
            {
                "id": len(rows) + 1,
                "speaker": match.group("speaker").lower(),
                "timestamp": match.group("timestamp"),
                "content": match.group("content").strip(),
                "classification": None,
                "vulnerability": None,
            }
        )
    return rows


def normalize_speaker(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"system", "ai", "assistant", "bot"}:
        return "system"
    if lowered in {"user", "human", "client"}:
        return "user"
    return lowered


def parse_court_transcript_records(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = COURT_TRANSCRIPT_PATTERN.match(line)
        if not match:
            continue
        rows.append(
            {
                "id": len(rows) + 1,
                "speaker": normalize_speaker(match.group("speaker")),
                "timestamp": match.group("timestamp"),
                "content": match.group("content").strip(),
                "classification": None,
                "vulnerability": None,
            }
        )
    return rows


def parse_axiom_json_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    candidates = None
    if isinstance(data, dict):
        for key in ("messages", "transcript", "items", "chats"):
            if isinstance(data.get(key), list):
                candidates = data[key]
                break
    if candidates is None:
        raise ValueError("AXIOM JSON parser could not find a transcript-like message array")
    rows = []
    for item in candidates:
        content = item.get("content") or item.get("message") or item.get("body") or ""
        speaker = item.get("speaker") or item.get("author") or item.get("sender") or ""
        timestamp = item.get("timestamp") or item.get("time") or item.get("created_at")
        rows.append(
            {
                "id": len(rows) + 1,
                "speaker": normalize_speaker(str(speaker)),
                "timestamp": timestamp,
                "content": str(content).strip(),
                "classification": None,
                "vulnerability": None,
            }
        )
    return rows


def parse_ufed_xml_records(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    rows = []
    for node in root.iter():
        tag = node.tag.lower().split("}")[-1]
        if tag not in {"message", "item", "record"}:
            continue
        attrib = {k.lower(): v for k, v in node.attrib.items()}
        speaker = attrib.get("speaker") or attrib.get("author") or attrib.get("sender")
        timestamp = attrib.get("timestamp") or attrib.get("time")
        content = attrib.get("content") or attrib.get("body") or (node.text or "").strip()
        if content is None:
            content = ""
        if not speaker or not str(content).strip():
            children = {child.tag.lower().split("}")[-1]: (child.text or "").strip() for child in list(node)}
            speaker = speaker or children.get("speaker") or children.get("author") or children.get("sender")
            timestamp = timestamp or children.get("timestamp") or children.get("time")
            content = (str(content).strip() if content is not None else "") or children.get("content") or children.get("body") or children.get("message") or ""
        normalized_content = str(content).strip() if content is not None else ""
        if speaker and normalized_content:
            rows.append(
                {
                    "id": len(rows) + 1,
                    "speaker": normalize_speaker(str(speaker)),
                    "timestamp": timestamp,
                    "content": normalized_content,
                    "classification": None,
                    "vulnerability": None,
                }
            )
    if not rows:
        raise ValueError("UFED XML parser could not extract any messages")
    return rows


def validate_transcript(messages: Iterable[dict]) -> list[str]:
    errors: list[str] = []
    messages = list(messages)
    if not messages:
        errors.append("TEST_INGEST_009 failed: input contains zero messages")
        return errors
    speakers = {msg["speaker"] for msg in messages}
    if len(speakers) < 2 or not {"system", "user"}.issubset(speakers):
        errors.append("TEST_INGEST_010 failed: transcript must include both system and user speakers")
    for msg in messages:
        if msg["speaker"] not in {"system", "user"}:
            errors.append(f"Invalid speaker in message {msg['id']}: {msg['speaker']}")
        if not msg["content"]:
            errors.append(f"Empty content in message {msg['id']}")
    return errors


def ingest_case(
    input_path: Path,
    case_id: str,
    examiner_id: str,
    fmt: str,
    cases_root: Path,
) -> IngestResult:
    if not input_path.exists():
        raise FileNotFoundError("TEST_INGEST_001 failed: source file does not exist")
    parser = {
        "json": parse_json_records,
        "csv": parse_csv_records,
        "text": parse_text_records,
        "plain": parse_text_records,
        "court": parse_court_transcript_records,
        "axiom": parse_axiom_json_records,
        "ufed": parse_ufed_xml_records,
    }.get(fmt.lower())
    if parser is None:
        raise ValueError(f"Unsupported format: {fmt}")

    source_hash = sha256_file(input_path)
    messages = parser(input_path)
    errors = validate_transcript(messages)
    if errors:
        raise ValueError("\n".join(errors))

    case_dir = ensure_dir(cases_root / case_id)
    normalized = {
        "trace_version": "2.0.0",
        "case_id": case_id,
        "source_hash_sha256": source_hash,
        "ingest_timestamp": utc_now_iso(),
        "examiner_id": examiner_id,
        "transcript": messages,
    }
    normalized_path = case_dir / "source_transcript.json"
    write_json(normalized_path, normalized)

    chain = [
        {
            "event": "ingest",
            "timestamp": utc_now_iso(),
            "examiner_id": examiner_id,
            "source_path": str(input_path),
            "source_hash_sha256": source_hash,
            "normalized_hash_sha256": sha256_text(normalized_path.read_text(encoding="utf-8")),
        }
    ]
    write_json(case_dir / "chain_of_custody.json", chain)
    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "ingest_completed",
            "case_id": case_id,
            "examiner_id": examiner_id,
            "message_count": len(messages),
            "source_hash_sha256": source_hash,
        },
    )
    return IngestResult(case_dir, normalized_path, source_hash, len(messages))
