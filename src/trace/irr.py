from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from trace.storage import append_jsonl, read_json, utc_now_iso, write_json


def cohen_kappa(values_a: list[str], values_b: list[str]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Cohen's kappa requires equal-length input")
    if not values_a:
        return 1.0
    observed = sum(1 for left, right in zip(values_a, values_b, strict=True) if left == right) / len(values_a)
    counts_a = Counter(values_a)
    counts_b = Counter(values_b)
    categories = set(counts_a) | set(counts_b)
    expected = sum((counts_a[c] / len(values_a)) * (counts_b[c] / len(values_b)) for c in categories)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def _distance(a: int, b: int, value_range: int) -> float:
    if value_range <= 0:
        return 0.0
    return ((a - b) / value_range) ** 2


def krippendorff_alpha_nominal(values_a: list[str], values_b: list[str]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Krippendorff alpha requires equal-length input")
    n = len(values_a)
    if n == 0:
        return 1.0
    observed = sum(0 if left == right else 1 for left, right in zip(values_a, values_b, strict=True)) / n
    pooled = values_a + values_b
    counts = Counter(pooled)
    total = len(pooled)
    expected = 1 - sum((count / total) ** 2 for count in counts.values())
    if expected == 0:
        return 1.0
    return 1 - (observed / expected)


def krippendorff_alpha_ordinal(values_a: list[int], values_b: list[int]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Krippendorff alpha requires equal-length input")
    if not values_a:
        return 1.0
    min_value = min(values_a + values_b)
    max_value = max(values_a + values_b)
    value_range = max_value - min_value
    observed = sum(_distance(left, right, value_range) for left, right in zip(values_a, values_b, strict=True)) / len(values_a)

    pooled = values_a + values_b
    total_pairs = 0
    total_distance = 0.0
    for left in pooled:
        for right in pooled:
            total_distance += _distance(left, right, value_range)
            total_pairs += 1
    expected = total_distance / total_pairs if total_pairs else 0.0
    if expected == 0:
        return 1.0
    return 1 - (observed / expected)


def import_second_coder(case_dir: Path, coder_file: Path) -> Path:
    data = read_json(coder_file)
    output_path = case_dir / "coder2_classified_transcript.json"
    write_json(output_path, data)
    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "irr_import",
            "coder_file": str(coder_file),
            "stored_as": str(output_path),
        },
    )
    return output_path


def _collect_metrics(transcript: Iterable[dict], transcript2: Iterable[dict]) -> tuple[list[str], list[str], list[str], list[str], list[int], list[int]]:
    behavior_1: list[str] = []
    behavior_2: list[str] = []
    roles_1: list[str] = []
    roles_2: list[str] = []
    vuln_1: list[int] = []
    vuln_2: list[int] = []

    for left, right in zip(transcript, transcript2, strict=True):
        if left["speaker"] != right["speaker"]:
            raise ValueError("Transcript mismatch between coders")
        if left["speaker"] == "system":
            behavior_1.append(left["classification"]["behavioral_category"])
            behavior_2.append(right["classification"]["behavioral_category"])
            roles_1.append(left["classification"]["ai_role"])
            roles_2.append(right["classification"]["ai_role"])
        else:
            vuln_1.append(int(left["classification"]["vulnerability_level"]))
            vuln_2.append(int(right["classification"]["vulnerability_level"]))
    return behavior_1, behavior_2, roles_1, roles_2, vuln_1, vuln_2


def compute_irr(case_dir: Path) -> dict:
    coder1 = read_json(case_dir / "classified_transcript.json")
    coder2 = read_json(case_dir / "coder2_classified_transcript.json")
    behavior_1, behavior_2, roles_1, roles_2, vuln_1, vuln_2 = _collect_metrics(
        coder1["transcript"], coder2["transcript"]
    )
    stats = {
        "krippendorff_alpha_behavioral": round(krippendorff_alpha_nominal(behavior_1, behavior_2), 4),
        "krippendorff_alpha_vulnerability": round(krippendorff_alpha_ordinal(vuln_1, vuln_2), 4),
        "cohen_kappa_behavioral": round(cohen_kappa(behavior_1, behavior_2), 4),
        "cohen_kappa_ai_roles": round(cohen_kappa(roles_1, roles_2), 4),
    }
    write_json(case_dir / "irr_statistics.json", stats)
    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "irr_computed",
            "statistics": stats,
        },
    )
    return stats
