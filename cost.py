"""Cost estimation for the Cost agent.

Uses a small offline price table (approximate us-east-1 on-demand USD/month) so the estimate works
without credentials and is deterministic in tests. `PricingClient` can be swapped in to query the
AWS Price List API live; the table is a documented fallback, not a source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Resource

HOURS_PER_MONTH = 730

# Approximate on-demand us-east-1 prices. Verify against the AWS Pricing API before quoting externally.
EC2_HOURLY = {
    "t2.micro": 0.0116, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336,
    "m5.large": 0.096, "m6g.large": 0.077, "m7g.large": 0.0816, "m4.large": 0.10, "m4.xlarge": 0.20,
    "c4.large": 0.10, "c5.large": 0.085, "r4.large": 0.133, "r5.large": 0.126,
}
RDS_HOURLY = {"db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068, "db.m5.large": 0.171,
              "db.m5.xlarge": 0.342, "db.r5.large": 0.24}
EBS_GB_MONTH = {"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}

# current-gen replacement used for the "after fixes" estimate
PREV_GEN_UPGRADE = {"t2.micro": "t3.micro", "m4.large": "m6g.large", "m4.xlarge": "m6g.large",
                    "c4.large": "c5.large", "r4.large": "r5.large"}


@dataclass(frozen=True)
class CostLine:
    resource_id: str
    description: str
    monthly_usd: float


def _num(v: Any, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def estimate_resource(r: Resource, *, optimized: bool = False) -> list[CostLine]:
    p = r.properties
    if r.type == "AWS::EC2::Instance":
        it = str(p.get("InstanceType", "t3.micro"))
        if optimized:
            it = PREV_GEN_UPGRADE.get(it, it)
        price = EC2_HOURLY.get(it)
        if price is not None:
            return [CostLine(r.logical_id, f"EC2 {it}", round(price * HOURS_PER_MONTH, 2))]
    elif r.type == "AWS::RDS::DBInstance":
        cls = str(p.get("DBInstanceClass", "db.t3.micro"))
        price = RDS_HOURLY.get(cls)
        if price is not None:
            mult = 2 if str(p.get("MultiAZ")).lower() == "true" else 1
            return [CostLine(r.logical_id, f"RDS {cls}{' Multi-AZ' if mult == 2 else ''}",
                             round(price * HOURS_PER_MONTH * mult, 2))]
    elif r.type == "AWS::EC2::Volume":
        vt = str(p.get("VolumeType", "gp2"))
        if optimized and vt == "gp2":
            vt = "gp3"
        size = _num(p.get("Size"), 8)
        return [CostLine(r.logical_id, f"EBS {vt} {int(size)} GB", round(EBS_GB_MONTH.get(vt, 0.10) * size, 2))]
    return []


def estimate(resources: list[Resource], *, optimized: bool = False) -> dict[str, Any]:
    lines = [ln for r in resources for ln in estimate_resource(r, optimized=optimized)]
    return {"total_monthly_usd": round(sum(l.monthly_usd for l in lines), 2),
            "lines": [l.__dict__ for l in lines], "optimized": optimized}


def savings(resources: list[Resource]) -> dict[str, Any]:
    before, after = estimate(resources), estimate(resources, optimized=True)
    b, a = before["total_monthly_usd"], after["total_monthly_usd"]
    return {"before_monthly_usd": b, "after_monthly_usd": a, "saved_monthly_usd": round(b - a, 2),
            "saved_pct": round((b - a) / b * 100, 1) if b else 0.0,
            "assumption": "Offline approximate us-east-1 on-demand prices; verify with the AWS Pricing API."}
