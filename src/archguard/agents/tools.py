"""Strands tool wrappers around the deterministic core.

The same functions are deployed as a Lambda behind AgentCore Gateway (see tools_handler.py) so any
MCP client can use them; inside the Runtime we call them in-process to avoid a network hop.
"""

from __future__ import annotations

import json

from strands import tool

from .. import tools_handler as th


@tool
def scan_template(template: str) -> str:
    """Scan a CloudFormation/CDK-synth/Terraform-plan document and return findings as JSON.

    Args:
        template: Full text of the IaC document.
    """
    return json.dumps(th.scan_template({"template": template}))


@tool
def estimate_cost(template: str) -> str:
    """Estimate monthly cost before/after cost-optimization fixes, as JSON.

    Args:
        template: Full text of the IaC document.
    """
    return json.dumps(th.estimate_cost({"template": template}))


@tool
def apply_fixes(template: str, rule_ids: list[str] | None = None) -> str:
    """Apply deterministic remediations, re-scan, and return the patched template plus verification.

    Args:
        template: Full text of the CloudFormation template.
        rule_ids: Optional subset of rule IDs to fix; all fixable findings if omitted.
    """
    return json.dumps(th.apply_fixes({"template": template, "rule_ids": rule_ids}))
