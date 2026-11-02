"""Applies deterministic `fix_hint` patches to a CloudFormation template.

The Fix agent (LLM) may *propose* richer changes, but the guaranteed-safe baseline is this patcher:
it only sets properties the rule engine explicitly declared as the remediation, then the result is
re-scanned to prove the finding is gone (see `verify_fixes`).
"""

from __future__ import annotations

import copy
import io
from typing import Any

import yaml

from .models import Finding
from .parser import _CfnLoader, parse_cloudformation
from .rules import scan


def _set_path(props: dict[str, Any], path: str, value: Any) -> None:
    keys = path.split(".")
    cur = props
    for k in keys[:-1]:
        nxt = cur.get(k)
        if isinstance(nxt, list):  # e.g. SecurityGroupIngress.CidrIp -> patch every entry
            for item in nxt:
                if isinstance(item, dict):
                    item[keys[-1]] = value
            return
        cur = cur.setdefault(k, {})
    cur[keys[-1]] = value


def patch_template(text: str, findings: list[Finding]) -> str:
    doc = yaml.load(text, Loader=_CfnLoader)
    out = copy.deepcopy(doc)
    for f in findings:
        if not f.fix_hint:
            continue
        res = (out.get("Resources") or {}).get(f.resource_id)
        if not res:
            continue
        props = res.setdefault("Properties", {})
        for path, value in f.fix_hint.items():
            _set_path(props, path, value)
    buf = io.StringIO()
    yaml.safe_dump(out, buf, sort_keys=False)
    return buf.getvalue()


def verify_fixes(original: str, patched: str) -> dict[str, Any]:
    before = {f.key for f in scan(parse_cloudformation(original))}
    after = {f.key for f in scan(parse_cloudformation(patched))}
    return {"findings_before": len(before), "findings_after": len(after),
            "resolved": sorted(map("::".join, before - after)),
            "remaining": sorted(map("::".join, after))}
