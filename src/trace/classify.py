from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import sys
from pathlib import Path

from trace.llm import LLMConfig, classify_system_with_provider, classify_user_with_provider
from trace.heuristics import classify_system_message, classify_user_message
from trace.schemas import AI_ROLES, BEHAVIORAL_SCHEMA_VERSION, VULNERABILITY_LEVELS, VULNERABILITY_SCHEMA_VERSION
from trace.storage import append_jsonl, read_json, utc_now_iso, write_json


@dataclass
class ClassificationResult:
    classified_path: Path
    message_count: int


def calibrate_user_vulnerability_from_state(
    level: int,
    indicators: list[str],
    confidence: float,
    reasoning: str,
    prior_user_vulnerabilities: list[int],
) -> tuple[int, float, str]:
    if not prior_user_vulnerabilities:
        return level, confidence, reasoning
    recent = prior_user_vulnerabilities[-2:]
    trajectory = prior_user_vulnerabilities[-3:]
    prior_max = max(recent, default=0)
    trajectory_max = max(trajectory, default=0)
    elevated_recent_count = sum(1 for value in trajectory if value >= 3)
    severe_recent_count = sum(1 for value in trajectory if value >= 4)
    has_signal = bool(indicators)
    calibrated_level = level
    calibrated_reasoning = reasoning
    calibrated_confidence = confidence

    if prior_max >= 4 and level >= 3:
        calibrated_level = max(level, 4)
    elif prior_max >= 3 and level >= 2 and has_signal:
        calibrated_level = max(level, 3)

    if has_signal and elevated_recent_count >= 2:
        if severe_recent_count >= 2 and trajectory_max >= 4 and level >= 3:
            calibrated_level = max(calibrated_level, 4)
        elif level >= 2:
            calibrated_level = max(calibrated_level, 3)

    if calibrated_level > level:
        calibrated_confidence = max(confidence, 0.8)
        calibrated_reasoning = (
            f"{reasoning} "
            f"TRACE state calibration raised vulnerability from {level} to {calibrated_level} "
            f"based on recent elevated user-risk trajectory."
        ).strip()
    return calibrated_level, calibrated_confidence, calibrated_reasoning


def build_state_summary(classified_messages: list[dict], window_size: int = 20) -> str:
    relevant = classified_messages[-window_size:]
    max_vuln = max(
        ((msg.get("vulnerability") or 0) for msg in relevant if msg["speaker"] == "user"),
        default=0,
    )
    categories = [
        msg["classification"]["behavioral_category"]
        for msg in relevant
        if msg["speaker"] == "system" and msg.get("classification")
    ]
    common = Counter(categories).most_common(1)
    trend = common[0][0] if common else "no_harmful_behavior"
    return f"Current vulnerability level: {VULNERABILITY_LEVELS[max_vuln]['label']}; behavioral trend: {trend}."


def build_window(messages: list[dict], current_index: int, window_size: int) -> list[dict]:
    start = max(0, current_index - window_size + 1)
    return [
        {"id": msg["id"], "speaker": msg["speaker"], "content": msg["content"], "timestamp": msg.get("timestamp")}
        for msg in messages[start : current_index + 1]
    ]


def review_classification(record: dict, review_mode: str) -> dict:
    classification = record["classification"]
    classification.setdefault("override_rationale", "")
    if review_mode == "auto":
        classification["decision"] = "accepted"
        return classification
    if review_mode == "flag-low-confidence" and classification["requires_review"]:
        classification["decision"] = "flagged"
        return classification
    if review_mode == "interactive" and sys.stdin.isatty():
        prompt = (
            f"\nMessage #{record['id']} ({record['speaker']}): {record['content']}\n"
            f"Suggestion: {classification}\n"
            "[A]ccept / [F]lag / [O]verride? "
        )
        choice = input(prompt).strip().lower()
        if choice == "f":
            classification["decision"] = "flagged"
        elif choice == "o":
            classification["decision"] = "overridden"
            if record["speaker"] == "user":
                classification["vulnerability_level"] = int(input("Override vulnerability level (0-4): ").strip())
            else:
                classification["behavioral_category"] = input("Override behavioral category: ").strip()
                classification["behavioral_subcategory"] = input("Override behavioral subcategory: ").strip()
                classification["ai_role"] = input("Override AI role: ").strip()
            classification["reasoning"] = input("Override reasoning: ").strip() or classification["reasoning"]
            classification["override_rationale"] = input("Override rationale: ").strip()
        else:
            classification["decision"] = "accepted"
        return classification
    classification["decision"] = "accepted"
    return classification


def classify_case(
    case_dir: Path,
    examiner_id: str,
    confidence_threshold: float = 0.6,
    mode: str = "heuristic",
    provider: str = "heuristic",
    model: str = "trace-heuristic-v1",
    temperature: float = 0.0,
    window_size: int = 20,
    review_mode: str = "auto",
    replay_dir: Path | None = None,
    replay_mode: str = "off",
) -> ClassificationResult:
    source = read_json(case_dir / "source_transcript.json")
    transcript = source["transcript"]
    classified: list[dict] = []
    current_user_vulnerability = 0
    prior_user_vulnerabilities: list[int] = []
    config = LLMConfig(provider=provider, model=model, temperature=temperature)
    config.cache_dir = case_dir / ".llm_cache"
    config.replay_dir = replay_dir
    config.replay_mode = replay_mode

    for index, message in enumerate(transcript):
        record = dict(message)
        state_summary = build_state_summary(classified, window_size=window_size) if classified else "Current vulnerability level: Baseline; behavioral trend: no_harmful_behavior."
        window_messages = build_window(transcript, index, window_size)
        if record["speaker"] == "user":
            level, indicators, confidence, reasoning = classify_user_with_provider(
                record["content"],
                state_summary,
                window_messages,
                config,
            )
            if provider in {"openrouter", "ollama"}:
                level, confidence, reasoning = calibrate_user_vulnerability_from_state(
                    level,
                    indicators,
                    confidence,
                    reasoning,
                    prior_user_vulnerabilities,
                )
            record["vulnerability"] = level
            record["classification"] = {
                "schema_version": VULNERABILITY_SCHEMA_VERSION,
                "type": "user_vulnerability",
                "vulnerability_level": level,
                "indicators_observed": indicators,
                "reasoning": reasoning,
                "confidence": confidence,
                "requires_review": confidence < confidence_threshold,
                "decision": "pending",
                "override_rationale": "",
            }
            record["classification"] = review_classification(record, review_mode)
            current_user_vulnerability = level
            prior_user_vulnerabilities.append(level)
        else:
            category, subcategory, role, confidence, reasoning = classify_system_with_provider(
                record["content"],
                current_user_vulnerability,
                state_summary,
                window_messages,
                config,
            )
            record["classification"] = {
                "schema_version": BEHAVIORAL_SCHEMA_VERSION,
                "type": "system_behavioral",
                "behavioral_category": category,
                "behavioral_subcategory": subcategory,
                "ai_role": role if role in AI_ROLES else "none",
                "reasoning": reasoning,
                "confidence": confidence,
                "requires_review": confidence < confidence_threshold,
                "decision": "pending",
                "override_rationale": "",
            }
            record["classification"] = review_classification(record, review_mode)
        record["state_summary"] = build_state_summary(classified + [record], window_size=window_size)
        classified.append(record)
        append_jsonl(
            case_dir / "audit_log.jsonl",
            {
                "timestamp": utc_now_iso(),
                "event": "classification_recorded",
                "case_id": source["case_id"],
                "examiner_id": examiner_id,
                "message_id": record["id"],
                "speaker": record["speaker"],
                "decision": record["classification"]["decision"],
                "requires_review": record["classification"]["requires_review"],
                "provider": provider,
                "model": model,
            },
        )

    output = {
        "trace_version": source["trace_version"],
        "case_id": source["case_id"],
        "classified_timestamp": utc_now_iso(),
        "examiner_id": examiner_id,
        "classification_mode": "manual" if mode == "manual" else "heuristic_assisted_human_reviewed",
        "llm_provider": "none" if mode == "manual" else provider,
        "model_id": "manual-human-review" if mode == "manual" else model,
        "temperature": temperature,
        "window_size": window_size,
        "review_mode": review_mode,
        "transcript": classified,
    }
    classified_path = case_dir / "classified_transcript.json"
    write_json(classified_path, output)
    return ClassificationResult(classified_path, len(classified))
