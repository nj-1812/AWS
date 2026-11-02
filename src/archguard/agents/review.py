"""Supervisor + specialist agents ("agents as tools" pattern in Strands).

Flow:
  1. Deterministic scan produces ground-truth findings (no hallucinated findings possible).
  2. Specialist agents (Haiku) each explain/prioritize the findings of ONE Well-Architected pillar.
  3. The supervisor (Sonnet) merges them into an executive review and decides which fixes to apply.
"""

from __future__ import annotations

import json
from typing import Any

from strands import Agent, tool
from strands.models import BedrockModel

from ..models import Pillar
from . import config
from .tools import apply_fixes, estimate_cost, scan_template

SPECIALIST_PROMPT = """You are an AWS Well-Architected {pillar} specialist.
You receive scanner findings (JSON) for ONE template. Rules:
- Only discuss findings present in the input; never invent findings or resource names.
- For each finding: explain the real-world risk in one sentence, cite its best-practice ID, and
  state the minimal fix. Order by severity then blast radius.
- If the list is empty, reply exactly: "No {pillar} findings."
Keep the answer under 250 words."""

SUPERVISOR_PROMPT = """You are a senior AWS Solutions Architect writing a Well-Architected review.
Workflow you MUST follow:
1. Call scan_template once with the customer's template.
2. Delegate to each pillar specialist tool with ONLY that pillar's findings.
3. Call estimate_cost for the cost section.
4. Call apply_fixes and report the verification numbers (findings before/after) exactly as returned.
Output markdown with: Executive summary (3 bullets), Findings by pillar, Cost impact, Fix verification,
and Residual risks needing human judgment. Never claim a fix was applied unless apply_fixes verified it."""


def _bedrock(model_id: str) -> BedrockModel:
    kwargs: dict[str, Any] = {"model_id": model_id, "region_name": config.REGION, "temperature": 0.2}
    if config.GUARDRAIL_ID:
        kwargs.update(guardrail_id=config.GUARDRAIL_ID, guardrail_version=config.GUARDRAIL_VERSION)
    return BedrockModel(**kwargs)


def _make_specialist_tool(pillar: Pillar):
    agent = Agent(model=_bedrock(config.model_for("specialist")),
                  system_prompt=SPECIALIST_PROMPT.format(pillar=pillar.value.replace("_", " ")), callback_handler=None)

    @tool(name=f"{pillar.value}_specialist", description=f"Review findings for the {pillar.value} pillar.")
    def _specialist(findings_json: str) -> str:
        return str(agent(findings_json))

    return _specialist


def build_supervisor(*, deep: bool = False) -> Agent:
    specialists = [_make_specialist_tool(p) for p in (Pillar.SECURITY, Pillar.RELIABILITY, Pillar.COST,
                                                       Pillar.OPERATIONAL_EXCELLENCE)]
    return Agent(model=_bedrock(config.model_for("supervisor", deep=deep)), system_prompt=SUPERVISOR_PROMPT,
                 tools=[scan_template, estimate_cost, apply_fixes, *specialists], callback_handler=None)


def review_template(template: str, *, deep: bool = False) -> dict[str, Any]:
    supervisor = build_supervisor(deep=deep)
    result = supervisor(f"Review this infrastructure template:\n\n{template}")
    usage = getattr(getattr(result, "metrics", None), "accumulated_usage", {}) or {}
    return {"report_markdown": str(result), "usage": json.loads(json.dumps(usage, default=str))}
