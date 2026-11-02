"""Benchmark evaluation: precision / recall / F1 of the scanner against seeded ground truth,
plus fix-verification rate (what fraction of findings the patcher provably resolves).

    python -m archguard.evaluate benchmark/generated
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from .parser import parse_text
from .patcher import patch_template, verify_fixes
from .rules import scan


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def evaluate(bench_dir: str | Path) -> dict[str, Any]:
    d = Path(bench_dir)
    labels: dict[str, list[list[str]]] = json.loads((d / "labels.json").read_text())
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    tp = fp = fn = 0
    fixable_total = resolved_total = 0
    for name, expected in labels.items():
        text = (d / name).read_text()
        findings = scan(parse_text(text, name))
        got = {f.key for f in findings}
        exp = {(r, res) for r, res in expected}
        for k in got & exp:
            per_rule[k[0]]["tp"] += 1
        for k in got - exp:
            per_rule[k[0]]["fp"] += 1
        for k in exp - got:
            per_rule[k[0]]["fn"] += 1
        tp, fp, fn = tp + len(got & exp), fp + len(got - exp), fn + len(exp - got)
        fixable = [f for f in findings if f.fix_hint]
        if fixable:
            v = verify_fixes(text, patch_template(text, findings))
            fixable_total += len(fixable)
            resolved_total += len({f.key for f in fixable} & {tuple(x.split("::", 1)) for x in v["resolved"]})
    return {
        "cases": len(labels), "seeded_findings": tp + fn,
        "overall": {"tp": tp, "fp": fp, "fn": fn, **_prf(tp, fp, fn)},
        "per_rule": {r: {**c, **_prf(**c)} for r, c in sorted(per_rule.items())},
        "fix_verification_rate": round(resolved_total / fixable_total, 4) if fixable_total else None,
        "fixable_findings": fixable_total,
    }


def main() -> None:
    res = evaluate(sys.argv[1] if len(sys.argv) > 1 else "benchmark/generated")
    o = res["overall"]
    print(f"cases={res['cases']} seeded={res['seeded_findings']} "
          f"precision={o['precision']:.3f} recall={o['recall']:.3f} f1={o['f1']:.3f}")
    print(f"fix verification: {res['fix_verification_rate']} of {res['fixable_findings']} fixable findings resolved by re-scan")
    for r, c in res["per_rule"].items():
        print(f"  {r:8s} tp={c['tp']:3d} fp={c['fp']:3d} fn={c['fn']:3d} f1={c['f1']:.2f}")
    Path("benchmark/results.json").write_text(json.dumps(res, indent=2))
    sys.exit(0 if o["f1"] >= 0.95 else 1)


if __name__ == "__main__":
    main()
