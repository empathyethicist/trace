from __future__ import annotations

SYSTEM_BEHAVIORAL_TEMPLATE_VERSION = "sbc_v1.0"
USER_VULNERABILITY_TEMPLATE_VERSION = "uvc_v1.0"
STATE_SUMMARY_TEMPLATE_VERSION = "ssg_v1.0"

SYSTEM_BEHAVIORAL_TEMPLATE = """You are a forensic classification assistant.
Classify a system message using the Zhang et al. (2025) schema.
Return valid JSON with behavioral_category, behavioral_subcategory, ai_role,
reasoning, confidence.
"""

USER_VULNERABILITY_TEMPLATE = """You are a forensic classification assistant.
Classify a user message for vulnerability level using the TRACE C-SSRS-derived
scale. Return valid JSON with vulnerability_level, indicators_observed,
reasoning, confidence.
"""

STATE_SUMMARY_TEMPLATE = """Summarize current vulnerability level, behavioral
trend, and unresolved crisis indicators in under 100 words."""


def prompt_template_manifest() -> dict[str, str]:
    return {
        "system_behavioral": SYSTEM_BEHAVIORAL_TEMPLATE_VERSION,
        "user_vulnerability": USER_VULNERABILITY_TEMPLATE_VERSION,
        "state_summary": STATE_SUMMARY_TEMPLATE_VERSION,
    }


def prompt_template_files() -> dict[str, str]:
    return {
        f"{SYSTEM_BEHAVIORAL_TEMPLATE_VERSION}.txt": SYSTEM_BEHAVIORAL_TEMPLATE,
        f"{USER_VULNERABILITY_TEMPLATE_VERSION}.txt": USER_VULNERABILITY_TEMPLATE,
        f"{STATE_SUMMARY_TEMPLATE_VERSION}.txt": STATE_SUMMARY_TEMPLATE,
    }
