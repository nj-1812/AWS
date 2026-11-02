"""Model routing: the right Claude model per job (cost per completed task is the metric that matters)."""

from __future__ import annotations

import os

# Global cross-region inference profiles on Bedrock (verified IDs as of Oct 2026).
SUPERVISOR_MODEL = os.getenv("ARCHGUARD_SUPERVISOR_MODEL", "global.anthropic.claude-sonnet-5-5")
SPECIALIST_MODEL = os.getenv("ARCHGUARD_SPECIALIST_MODEL", "global.anthropic.claude-haiku-5-5")
DEEP_REVIEW_MODEL = os.getenv("ARCHGUARD_DEEP_MODEL", "global.anthropic.claude-opus-5-5")

REGION = os.getenv("AWS_REGION", "us-east-1")
GUARDRAIL_ID = os.getenv("ARCHGUARD_GUARDRAIL_ID")  # optional; set by CDK
GUARDRAIL_VERSION = os.getenv("ARCHGUARD_GUARDRAIL_VERSION", "DRAFT")


def model_for(role: str, *, deep: bool = False) -> str:
    if role == "supervisor":
        return DEEP_REVIEW_MODEL if deep else SUPERVISOR_MODEL
    return SPECIALIST_MODEL
