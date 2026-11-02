"""Deterministic rule engine.

Each rule inspects one normalized `Resource` and returns zero or more `Finding`s, tagged with
the Well-Architected pillar and best-practice ID. Rules are intentionally deterministic: the LLM
agents *explain, prioritize and fix* findings, but never decide whether a misconfiguration exists.
That separation is what makes precision/recall measurable (see `archguard.evaluate`).
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from .models import Finding, Pillar, Resource, Severity

RuleFn = Callable[[Resource], Iterable[Finding]]
_REGISTRY: dict[str, tuple[frozenset[str], RuleFn]] = {}


def rule(rule_id: str, *resource_types: str) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        _REGISTRY[rule_id] = (frozenset(resource_types), fn)
        return fn

    return deco


def _f(res: Resource, rule_id: str, title: str, pillar: Pillar, sev: Severity, msg: str,
       fix: str, bp: str, hint: dict[str, Any] | None = None) -> Finding:
    return Finding(rule_id, title, pillar, sev, res.logical_id, res.type, msg, fix, bp, hint or {})


def _is_true(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


# ------------------------------------------------------------------------------------ S3
@rule("S3-001", "AWS::S3::Bucket")
def s3_encryption(r: Resource):
    if not r.properties.get("BucketEncryption"):
        yield _f(r, "S3-001", "S3 bucket without default encryption", Pillar.SECURITY, Severity.MEDIUM,
                 "No default server-side encryption is configured.",
                 "Add BucketEncryption with SSE-KMS (or SSE-S3 at minimum).", "SEC08-BP02",
                 {"BucketEncryption": {"ServerSideEncryptionConfiguration": [
                     {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}})


@rule("S3-002", "AWS::S3::Bucket")
def s3_public_access_block(r: Resource):
    pab = r.properties.get("PublicAccessBlockConfiguration") or {}
    required = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
    if not all(_is_true(pab.get(k)) for k in required):
        yield _f(r, "S3-002", "S3 bucket missing full Public Access Block", Pillar.SECURITY, Severity.HIGH,
                 "Public Access Block is absent or incomplete; the bucket could be made public.",
                 "Enable all four PublicAccessBlockConfiguration settings.", "SEC03-BP01",
                 {"PublicAccessBlockConfiguration": {k: True for k in required}})


@rule("S3-003", "AWS::S3::Bucket")
def s3_versioning(r: Resource):
    if (r.properties.get("VersioningConfiguration") or {}).get("Status") != "Enabled":
        yield _f(r, "S3-003", "S3 versioning disabled", Pillar.RELIABILITY, Severity.MEDIUM,
                 "Without versioning, overwritten or deleted objects cannot be recovered.",
                 "Enable VersioningConfiguration.Status = Enabled.", "REL09-BP01",
                 {"VersioningConfiguration": {"Status": "Enabled"}})


@rule("S3-004", "AWS::S3::Bucket")
def s3_public_acl(r: Resource):
    if r.properties.get("AccessControl") in ("PublicRead", "PublicReadWrite"):
        yield _f(r, "S3-004", "S3 bucket uses a public ACL", Pillar.SECURITY, Severity.CRITICAL,
                 f"AccessControl={r.properties['AccessControl']} exposes objects to the internet.",
                 "Remove the public ACL; serve content through CloudFront with OAC.", "SEC03-BP01",
                 {"AccessControl": "Private"})


# ------------------------------------------------------------------------------------ EC2 / SG
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis"}


def _ingress_rules(r: Resource) -> list[dict[str, Any]]:
    if r.type == "AWS::EC2::SecurityGroupIngress":  # standalone rule resource: its own properties are the rule
        return [r.properties]
    return [x for x in (r.properties.get("SecurityGroupIngress") or []) if isinstance(x, dict)]


def _as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@rule("SG-001", "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress")
def sg_open_sensitive(r: Resource):
    for ing in _ingress_rules(r):
        if ing.get("CidrIp") in ("0.0.0.0/0",) or ing.get("CidrIpv6") == "::/0":
            lo, hi = _as_int(ing.get("FromPort")), _as_int(ing.get("ToPort"))
            if lo is None or hi is None:
                continue
            for port, name in _SENSITIVE_PORTS.items():
                if lo <= port <= hi:
                    yield _f(r, "SG-001", f"{name} open to the internet", Pillar.SECURITY, Severity.CRITICAL,
                             f"Port {port} ({name}) is reachable from 0.0.0.0/0.",
                             "Restrict the CIDR to a bastion/VPN range, or use SSM Session Manager.",
                             "SEC05-BP01", {"SecurityGroupIngress.CidrIp": "10.0.0.0/8"})
                    return


@rule("SG-002", "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress")
def sg_all_ports(r: Resource):
    for ing in _ingress_rules(r):
        if str(ing.get("IpProtocol")) == "-1" and ing.get("CidrIp") == "0.0.0.0/0":
            yield _f(r, "SG-002", "Security group allows all traffic from anywhere", Pillar.SECURITY,
                     Severity.CRITICAL, "IpProtocol -1 from 0.0.0.0/0 disables network-layer isolation.",
                     "Allow only the specific ports and sources the workload needs.", "SEC05-BP01")
            return


# ------------------------------------------------------------------------------------ RDS
@rule("RDS-001", "AWS::RDS::DBInstance")
def rds_encryption(r: Resource):
    if not _is_true(r.properties.get("StorageEncrypted")):
        yield _f(r, "RDS-001", "RDS storage not encrypted", Pillar.SECURITY, Severity.HIGH,
                 "StorageEncrypted is not enabled.", "Enable StorageEncrypted with a KMS key (requires snapshot-restore on existing DBs).",
                 "SEC08-BP01", {"StorageEncrypted": True})


@rule("RDS-002", "AWS::RDS::DBInstance")
def rds_multi_az(r: Resource):
    if not _is_true(r.properties.get("MultiAZ")):
        yield _f(r, "RDS-002", "RDS instance is single-AZ", Pillar.RELIABILITY, Severity.HIGH,
                 "A single-AZ database has no automatic failover.", "Set MultiAZ: true for production workloads.",
                 "REL10-BP01", {"MultiAZ": True})


@rule("RDS-003", "AWS::RDS::DBInstance")
def rds_public(r: Resource):
    if _is_true(r.properties.get("PubliclyAccessible")):
        yield _f(r, "RDS-003", "RDS instance is publicly accessible", Pillar.SECURITY, Severity.CRITICAL,
                 "PubliclyAccessible=true places the database endpoint on the public internet.",
                 "Set PubliclyAccessible: false and place it in private subnets.", "SEC05-BP01",
                 {"PubliclyAccessible": False})


@rule("RDS-004", "AWS::RDS::DBInstance")
def rds_backups(r: Resource):
    days = _as_int(r.properties.get("BackupRetentionPeriod"))
    if days is not None and days < 7:
        yield _f(r, "RDS-004", "RDS backup retention under 7 days", Pillar.RELIABILITY, Severity.MEDIUM,
                 f"BackupRetentionPeriod is {days} day(s).", "Set BackupRetentionPeriod to at least 7.",
                 "REL09-BP03", {"BackupRetentionPeriod": 7})
    elif days is None:
        # CloudFormation default is 1 day
        yield _f(r, "RDS-004", "RDS backup retention under 7 days", Pillar.RELIABILITY, Severity.MEDIUM,
                 "BackupRetentionPeriod is unset (default 1 day).", "Set BackupRetentionPeriod to at least 7.",
                 "REL09-BP03", {"BackupRetentionPeriod": 7})


# ------------------------------------------------------------------------------------ IAM
def _statements(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement", [])
    return [s for s in (stmts if isinstance(stmts, list) else [stmts]) if isinstance(s, dict)]


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


@rule("IAM-001", "AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy")
def iam_wildcard(r: Resource):
    docs: list[Any] = [r.properties.get("PolicyDocument")]
    docs += [p.get("PolicyDocument") for p in (r.properties.get("Policies") or []) if isinstance(p, dict)]
    for doc in docs:
        for s in _statements(doc):
            if s.get("Effect") != "Allow":
                continue
            actions, resources = _as_list(s.get("Action", [])), _as_list(s.get("Resource", []))
            if "*" in actions and "*" in resources:
                yield _f(r, "IAM-001", "IAM policy grants Action:* on Resource:*", Pillar.SECURITY,
                         Severity.CRITICAL, "Full administrator access violates least privilege.",
                         "Scope Action and Resource to exactly what the workload needs.", "SEC03-BP02")
                return
            if any(isinstance(a, str) and a.endswith(":*") for a in actions) and "*" in resources:
                yield _f(r, "IAM-002", "IAM policy uses service-wide wildcard on all resources", Pillar.SECURITY,
                         Severity.HIGH, "Service-level wildcard actions on Resource:* are overly broad.",
                         "Enumerate specific actions and constrain Resource ARNs.", "SEC03-BP02")
                return


@rule("IAM-003", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group")
def iam_admin_managed(r: Resource):
    for arn in _as_list(r.properties.get("ManagedPolicyArns") or []):
        if isinstance(arn, str) and arn.endswith(":policy/AdministratorAccess"):
            yield _f(r, "IAM-003", "AdministratorAccess managed policy attached", Pillar.SECURITY, Severity.CRITICAL,
                     "The AWS-managed AdministratorAccess policy grants full account control.",
                     "Replace with a scoped customer-managed policy.", "SEC03-BP02")
            return


# ------------------------------------------------------------------------------------ EBS / EC2 cost
@rule("EBS-001", "AWS::EC2::Volume")
def ebs_encryption(r: Resource):
    if not _is_true(r.properties.get("Encrypted")):
        yield _f(r, "EBS-001", "EBS volume not encrypted", Pillar.SECURITY, Severity.MEDIUM,
                 "Volume data at rest is unencrypted.", "Set Encrypted: true.", "SEC08-BP01", {"Encrypted": True})


@rule("EBS-002", "AWS::EC2::Volume")
def ebs_gp2(r: Resource):
    if r.properties.get("VolumeType", "gp2") == "gp2":
        yield _f(r, "EBS-002", "EBS gp2 volume; gp3 is cheaper and faster", Pillar.COST, Severity.LOW,
                 "gp3 costs ~20% less per GB with a higher baseline performance.", "Switch VolumeType to gp3.",
                 "COST06-BP03", {"VolumeType": "gp3"})


_PREV_GEN = ("t2.", "m4.", "c4.", "r4.", "m3.", "c3.", "r3.")


@rule("EC2-001", "AWS::EC2::Instance")
def ec2_prev_gen(r: Resource):
    it = str(r.properties.get("InstanceType", ""))
    if it.startswith(_PREV_GEN):
        yield _f(r, "EC2-001", "Previous-generation EC2 instance type", Pillar.COST, Severity.LOW,
                 f"{it} is a previous generation; current generations offer better price/performance.",
                 "Move to the current generation (e.g. t3/t4g, m7g/m7i).", "COST06-BP02")


# ------------------------------------------------------------------------------------ DynamoDB / Lambda / SQS
@rule("DDB-001", "AWS::DynamoDB::Table")
def ddb_pitr(r: Resource):
    pitr = (r.properties.get("PointInTimeRecoverySpecification") or {}).get("PointInTimeRecoveryEnabled")
    if not _is_true(pitr):
        yield _f(r, "DDB-001", "DynamoDB point-in-time recovery disabled", Pillar.RELIABILITY, Severity.MEDIUM,
                 "Without PITR, accidental writes/deletes cannot be rolled back.",
                 "Enable PointInTimeRecoverySpecification.", "REL09-BP01",
                 {"PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}})


@rule("LAM-001", "AWS::Lambda::Function")
def lambda_tracing(r: Resource):
    if (r.properties.get("TracingConfig") or {}).get("Mode") != "Active":
        yield _f(r, "LAM-001", "Lambda X-Ray tracing disabled", Pillar.OPERATIONAL_EXCELLENCE, Severity.LOW,
                 "No distributed tracing makes failures hard to diagnose.", "Set TracingConfig.Mode = Active.",
                 "OPS08-BP01", {"TracingConfig": {"Mode": "Active"}})


@rule("SQS-001", "AWS::SQS::Queue")
def sqs_dlq(r: Resource):
    if not r.properties.get("RedrivePolicy"):
        yield _f(r, "SQS-001", "SQS queue has no dead-letter queue", Pillar.RELIABILITY, Severity.MEDIUM,
                 "Poison messages will be retried forever or lost.", "Add a RedrivePolicy with a DLQ.",
                 "REL05-BP01")


# ------------------------------------------------------------------------------------ engine
def all_rule_ids() -> list[str]:
    return sorted(_REGISTRY)


def _dlq_targets(resources: list[Resource]) -> set[str]:
    """Logical IDs of queues that act as another queue's dead-letter target (they need no DLQ themselves)."""
    out: set[str] = set()
    for r in resources:
        if r.type != "AWS::SQS::Queue":
            continue
        arn = (r.properties.get("RedrivePolicy") or {}).get("deadLetterTargetArn")
        if isinstance(arn, dict) and "Fn::GetAtt" in arn:
            out.add(str(_as_list(arn["Fn::GetAtt"])[0]))
    return out


def _is_cdk_internal(r: Resource) -> bool:
    """CDK-generated singleton helpers (custom-resource providers, log retention) are not user workloads."""
    return r.logical_id.startswith(("Custom", "LogRetention"))


def scan(resources: Iterable[Resource]) -> list[Finding]:
    """Run every applicable rule; de-duplicate by (rule_id, resource_id); sort by severity."""
    resources = list(resources)
    dlqs = _dlq_targets(resources)
    seen: dict[tuple[str, str], Finding] = {}
    for res in resources:
        if _is_cdk_internal(res):
            continue
        for rid, (types, fn) in _REGISTRY.items():
            if res.type in types:
                if rid == "SQS-001" and res.logical_id in dlqs:
                    continue
                for f in fn(res):
                    seen.setdefault(f.key, f)
    return sorted(seen.values(), key=lambda f: (-f.severity.weight, f.rule_id, f.resource_id))
