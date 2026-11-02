"""IaC parsing: CloudFormation (YAML/JSON, incl. `cdk synth` output) and Terraform plan JSON.

Everything is normalized into `Resource` objects with CloudFormation type names so a single
rule set covers both formats. Terraform resources are mapped through a small translation table.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import Resource


# --------------------------------------------------------------------------- CloudFormation
class _CfnLoader(yaml.SafeLoader):
    """YAML loader that understands CloudFormation short-form intrinsic tags (!Ref, !GetAtt...)."""


def _intrinsic(loader: yaml.Loader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    name = "Ref" if suffix == "Ref" else ("Condition" if suffix == "Condition" else f"Fn::{suffix}")
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {name: value}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def _resolve_refs(node: Any, defaults: dict[str, Any]) -> Any:
    """Substitute `!Ref Param` with the parameter's Default (static analysis best-effort)."""
    if isinstance(node, dict):
        if set(node) == {"Ref"} and node["Ref"] in defaults:
            return defaults[node["Ref"]]
        return {k: _resolve_refs(v, defaults) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_refs(v, defaults) for v in node]
    return node


def parse_cloudformation(text: str, source_file: str = "") -> list[Resource]:
    doc = yaml.load(text, Loader=_CfnLoader)  # JSON is valid YAML
    if not isinstance(doc, dict):
        return []
    resources = doc.get("Resources") or {}
    defaults = {k: v["Default"] for k, v in (doc.get("Parameters") or {}).items()
                if isinstance(v, dict) and "Default" in v}
    if defaults:
        resources = _resolve_refs(resources, defaults)
    out: list[Resource] = []
    for logical_id, body in resources.items():
        if not isinstance(body, dict) or "Type" not in body:
            continue
        out.append(
            Resource(
                logical_id=str(logical_id),
                type=str(body["Type"]),
                properties=body.get("Properties") or {},
                source_file=source_file,
            )
        )
    return out


# --------------------------------------------------------------------------- Terraform (plan JSON)
_TF_TYPE_MAP = {
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_instance": "AWS::EC2::Instance",
    "aws_ebs_volume": "AWS::EC2::Volume",
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_iam_policy": "AWS::IAM::ManagedPolicy",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_kms_key": "AWS::KMS::Key",
}


def _tf_normalize(tf_type: str, values: dict[str, Any]) -> dict[str, Any]:
    """Translate the Terraform attributes we care about into CloudFormation property shapes."""
    p: dict[str, Any] = {}
    if tf_type == "aws_s3_bucket":
        p["VersioningConfiguration"] = {"Status": "Enabled" if values.get("versioning") else "Suspended"}
        if values.get("server_side_encryption_configuration"):
            p["BucketEncryption"] = {"ServerSideEncryptionConfiguration": [{}]}
        if values.get("acl") in ("public-read", "public-read-write"):
            p["AccessControl"] = "PublicRead"
    elif tf_type == "aws_security_group":
        p["SecurityGroupIngress"] = [
            {
                "IpProtocol": r.get("protocol"),
                "FromPort": r.get("from_port"),
                "ToPort": r.get("to_port"),
                "CidrIp": (r.get("cidr_blocks") or [None])[0],
            }
            for r in values.get("ingress") or []
        ]
    elif tf_type == "aws_db_instance":
        p["StorageEncrypted"] = bool(values.get("storage_encrypted"))
        p["MultiAZ"] = bool(values.get("multi_az"))
        p["PubliclyAccessible"] = bool(values.get("publicly_accessible"))
        p["BackupRetentionPeriod"] = values.get("backup_retention_period", 0)
        p["DBInstanceClass"] = values.get("instance_class")
    elif tf_type == "aws_ebs_volume":
        p["Encrypted"] = bool(values.get("encrypted"))
    elif tf_type == "aws_instance":
        p["InstanceType"] = values.get("instance_type")
    else:
        p = {k.title().replace("_", ""): v for k, v in values.items()}
    return p


def parse_terraform_plan(text: str, source_file: str = "") -> list[Resource]:
    plan = json.loads(text)
    root = (plan.get("planned_values") or {}).get("root_module") or plan.get("values", {}).get("root_module") or {}
    out: list[Resource] = []

    def walk(module: dict[str, Any]) -> None:
        for res in module.get("resources", []):
            cfn_type = _TF_TYPE_MAP.get(res.get("type", ""))
            if not cfn_type:
                continue
            out.append(
                Resource(
                    logical_id=res.get("address", res.get("name", "unknown")),
                    type=cfn_type,
                    properties=_tf_normalize(res["type"], res.get("values") or {}),
                    source_file=source_file,
                )
            )
        for child in module.get("child_modules", []):
            walk(child)

    walk(root)
    return out


# --------------------------------------------------------------------------- dispatch
def parse_text(text: str, filename: str = "") -> list[Resource]:
    stripped = text.lstrip()
    if stripped.startswith("{") and '"planned_values"' in text or '"format_version"' in text[:400]:
        return parse_terraform_plan(text, filename)
    return parse_cloudformation(text, filename)


def parse_path(path: str | Path) -> list[Resource]:
    """Parse a single file, or every template-looking file under a directory."""
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        f for f in p.rglob("*") if f.suffix in {".yaml", ".yml", ".json", ".template"} and f.is_file()
    )
    resources: list[Resource] = []
    for f in files:
        try:
            resources.extend(parse_text(f.read_text(encoding="utf-8"), str(f)))
        except (yaml.YAMLError, json.JSONDecodeError, UnicodeDecodeError):
            continue  # not an IaC file; skip silently
    return resources
