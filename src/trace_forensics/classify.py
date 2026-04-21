from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import os
import sys
from pathlib import Path
from time import perf_counter

from trace_forensics.llm import LLMConfig, classify_system_with_provider, classify_user_with_provider
from trace_forensics.heuristics import (
    classify_system_message,
    classify_user_message,
    has_acute_crisis_language,
    has_practical_reorientation,
)
from trace_forensics.schemas import AI_ROLES, BEHAVIORAL_SCHEMA_VERSION, VULNERABILITY_LEVELS, VULNERABILITY_SCHEMA_VERSION
from trace_forensics.storage import append_jsonl, read_json, utc_now_iso, write_json


@dataclass
class ClassificationResult:
    classified_path: Path
    message_count: int
    timings: dict[str, float]


def calibrate_user_vulnerability_from_state(
    content: str,
    level: int,
    indicators: list[str],
    confidence: float,
    reasoning: str,
    prior_user_vulnerabilities: list[int],
) -> tuple[int, float, str, list[str]]:
    lexical_level, _, _ = classify_user_message(content)
    acute_language = has_acute_crisis_language(content)
    practical_reorientation = has_practical_reorientation(content)
    if not prior_user_vulnerabilities:
        return level, confidence, reasoning, []
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
    applied_rules: list[str] = []

    if prior_max >= 4 and level >= 3 and acute_language:
        calibrated_level = max(level, 4)
        if calibrated_level > level:
            applied_rules.append("state_raise_acute_trajectory")
    elif prior_max >= 3 and level >= 2 and has_signal:
        calibrated_level = max(level, 3)
        if calibrated_level > level:
            applied_rules.append("state_raise_elevated_trajectory")

    if has_signal and elevated_recent_count >= 2:
        if severe_recent_count >= 2 and trajectory_max >= 4 and level >= 3 and acute_language:
            calibrated_level = max(calibrated_level, 4)
            if calibrated_level > level and "state_raise_acute_trajectory" not in applied_rules:
                applied_rules.append("state_raise_acute_trajectory")
        elif level >= 2:
            calibrated_level = max(calibrated_level, 3)
            if calibrated_level > level and "state_raise_elevated_trajectory" not in applied_rules:
                applied_rules.append("state_raise_elevated_trajectory")

    if practical_reorientation and lexical_level == 0:
        if calibrated_level > 1:
            calibrated_level = 0
        elif level <= 1:
            calibrated_level = 0
        if calibrated_level < level:
            applied_rules.append("state_lower_practical_reorientation")
            calibrated_confidence = max(confidence, 0.8)
            calibrated_reasoning = (
                f"{reasoning} "
                f"TRACE state calibration lowered vulnerability from {level} to {calibrated_level} "
                f"because the current turn shifts back to concrete practical planning without direct distress indicators."
            ).strip()
            return calibrated_level, calibrated_confidence, calibrated_reasoning, applied_rules

    if lexical_level == 3 and not acute_language and calibrated_level > 3:
        calibrated_level = 3
        applied_rules.append("state_cap_without_acute_language")
        calibrated_confidence = max(confidence, 0.8)
        calibrated_reasoning = (
            f"{reasoning} "
            f"TRACE state calibration held vulnerability at 3 because the current turn reflects severe distress without explicit acute-crisis language."
        ).strip()
        return calibrated_level, calibrated_confidence, calibrated_reasoning, applied_rules

    if calibrated_level > level:
        calibrated_confidence = max(confidence, 0.8)
        calibrated_reasoning = (
            f"{reasoning} "
            f"TRACE state calibration raised vulnerability from {level} to {calibrated_level} "
            f"based on recent elevated user-risk trajectory."
        ).strip()
    return calibrated_level, calibrated_confidence, calibrated_reasoning, applied_rules


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
    adapter: str | None = None,
    temperature: float = 0.0,
    window_size: int = 20,
    review_mode: str = "auto",
    replay_dir: Path | None = None,
    replay_mode: str = "off",
) -> ClassificationResult:
    classify_started_at = perf_counter()
    source = read_json(case_dir / "source_transcript.json")
    source_loaded_at = perf_counter()
    transcript = source["transcript"]
    classified: list[dict] = []
    current_user_vulnerability = 0
    prior_user_vulnerabilities: list[int] = []
    provider_history: list[str] = []
    model_history: list[str] = []
    adapter_history: list[str] = []
    config = LLMConfig(provider=provider, model=model, temperature=temperature)
    config.cache_dir = case_dir / ".llm_cache"
    config.replay_dir = replay_dir
    config.replay_mode = replay_mode
    message_processing_seconds = 0.0
    audit_log_seconds = 0.0

    for index, message in enumerate(transcript):
        message_started_at = perf_counter()
        record = dict(message)
        state_summary = build_state_summary(classified, window_size=window_size) if classified else "Current vulnerability level: Baseline; behavioral trend: no_harmful_behavior."
        window_messages = build_window(transcript, index, window_size)
        if record["speaker"] == "user":
            (
                level,
                indicators,
                confidence,
                reasoning,
                actual_provider,
                actual_model,
                actual_adapter,
                calibration_provenance,
            ) = classify_user_with_provider(
                record["content"],
                state_summary,
                window_messages,
                config,
            )
            if provider in {"hosted", "ollama"}:
                level, confidence, reasoning, state_rules = calibrate_user_vulnerability_from_state(
                    record["content"],
                    level,
                    indicators,
                    confidence,
                    reasoning,
                    prior_user_vulnerabilities,
                )
                calibration_provenance["applied_rules"].extend(
                    rule for rule in state_rules if rule not in calibration_provenance["applied_rules"]
                )
            calibration_provenance["final_level"] = level
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
                "calibration_provenance": calibration_provenance,
            }
            record["classification"] = review_classification(record, review_mode)
            record["classification_provider"] = actual_provider
            record["classification_model"] = actual_model
            record["classification_adapter"] = actual_adapter
            current_user_vulnerability = level
            prior_user_vulnerabilities.append(level)
        else:
            (
                category,
                subcategory,
                role,
                confidence,
                reasoning,
                actual_provider,
                actual_model,
                actual_adapter,
            ) = classify_system_with_provider(
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
            record["classification_provider"] = actual_provider
            record["classification_model"] = actual_model
            record["classification_adapter"] = actual_adapter
        record["state_summary"] = build_state_summary(classified + [record], window_size=window_size)
        provider_history.append(actual_provider)
        model_history.append(actual_model)
        adapter_history.append(actual_adapter)
        classified.append(record)
        message_processing_seconds += perf_counter() - message_started_at
        audit_started_at = perf_counter()
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
                "requested_provider": provider,
                "requested_model": model,
                "provider": actual_provider,
                "model": actual_model,
                "adapter": actual_adapter,
            },
        )
        audit_log_seconds += perf_counter() - audit_started_at

    provider_counts = Counter(provider_history)
    model_counts = Counter(model_history)
    adapter_counts = Counter(adapter_history)
    effective_provider = provider_history[0] if len(provider_counts) == 1 else "mixed"
    effective_model = model_history[0] if len(model_counts) == 1 else "mixed"
    effective_adapter = adapter_history[0] if len(adapter_counts) == 1 else "mixed"

    output = {
        "trace_version": source["trace_version"],
        "case_id": source["case_id"],
        "classified_timestamp": utc_now_iso(),
        "examiner_id": examiner_id,
        "classification_mode": "manual" if mode == "manual" else "heuristic_assisted_human_reviewed",
        "requested_llm_provider": "none" if mode == "manual" else provider,
        "requested_model_id": "manual-human-review" if mode == "manual" else model,
        "llm_provider": "none" if mode == "manual" else effective_provider,
        "model_id": "manual-human-review" if mode == "manual" else effective_model,
        "llm_adapter": (
            "none"
            if mode == "manual"
            else (
                effective_adapter
            )
        ),
        "execution_summary": {
            "provider_counts": dict(provider_counts),
            "model_counts": dict(model_counts),
            "adapter_counts": dict(adapter_counts),
        },
        "temperature": temperature,
        "window_size": window_size,
        "review_mode": review_mode,
        "transcript": classified,
    }
    classified_path = case_dir / "classified_transcript.json"
    output["performance_summary"] = {
        "source_load_seconds": round(source_loaded_at - classify_started_at, 4),
        "message_processing_seconds": round(message_processing_seconds, 4),
        "audit_log_seconds": round(audit_log_seconds, 4),
        "write_output_seconds": 0.0,
        "total_seconds": 0.0,
        "llm_runtime_metrics": {
            key: round(value, 4) if isinstance(value, float) else value
            for key, value in (config.runtime_metrics or {}).items()
        },
    }
    write_started_at = perf_counter()
    write_json(classified_path, output)
    output["performance_summary"]["write_output_seconds"] = round(perf_counter() - write_started_at, 4)
    output["performance_summary"]["total_seconds"] = round(perf_counter() - classify_started_at, 4)
    write_json(classified_path, output)
    return ClassificationResult(classified_path, len(classified), output["performance_summary"])
