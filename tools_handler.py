"""Lambda handler exposing the deterministic scanner as MCP-style tools behind AgentCore Gateway.

AgentCore Gateway invokes a Lambda target with the tool arguments as the event and the tool name in
`context.client_context.custom["bedrockAgentCoreToolName"]` (format: `<target>___<tool>`).
We also accept a plain `{"tool": ..., "arguments": {...}}` event so the handler is unit-testable.
"""

from __future__ import annotations

import json
from typing import Any

from . import cost, patcher
from .parser import parse_text
from .rules import all_rule_ids, scan


def _tool_name(event: dict[str, Any], context: Any) -> str:
    try:
        raw = context.client_context.custom["bedrockAgentCoreToolName"]
        return raw.split("___", 1)[-1]
    except (AttributeError, KeyError, TypeError):
        return str(event.get("tool", ""))


def _args(event: dict[str, Any]) -> dict[str, Any]:
    return event.get("arguments", event)


def scan_template(a: dict[str, Any]) -> dict[str, Any]:
    findings = scan(parse_text(a["template"], a.get("filename", "template")))
    return {"finding_count": len(findings), "findings": [f.to_dict() for f in findings]}


def estimate_cost(a: dict[str, Any]) -> dict[str, Any]:
    return cost.savings(parse_text(a["template"], a.get("filename", "template")))


def apply_fixes(a: dict[str, Any]) -> dict[str, Any]:
    text = a["template"]
    findings = scan(parse_text(text))
    only = set(a.get("rule_ids") or [])
    chosen = [f for f in findings if not only or f.rule_id in only]
    patched = patcher.patch_template(text, chosen)
    return {"patched_template": patched, "verification": patcher.verify_fixes(text, patched)}


def list_rules(_: dict[str, Any]) -> dict[str, Any]:
    return {"rules": all_rule_ids()}


TOOLS = {"scan_template": scan_template, "estimate_cost": estimate_cost,
         "apply_fixes": apply_fixes, "list_rules": list_rules}


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    name = _tool_name(event, context)
    fn = TOOLS.get(name)
    if fn is None:
        return {"error": f"unknown tool '{name}'", "available": sorted(TOOLS)}
    try:
        return fn(_args(event))
    except KeyError as e:
        return {"error": f"missing required argument {e}"}
    except Exception as e:  # tool errors are returned to the agent, not raised, so it can recover
        return {"error": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":  # local debugging: python -m archguard.tools_handler < event.json
    import sys

    print(json.dumps(handler(json.load(sys.stdin)), indent=2))
