import json
from pathlib import Path

import pytest

from archguard import cost, patcher
from archguard.evaluate import evaluate
from archguard.parser import parse_text
from archguard.rules import scan
from archguard.tools_handler import handler

ROOT = Path(__file__).resolve().parents[1]
CASE = (ROOT / "benchmark/cases/case01_web_stack.yaml").read_text()


def ids(text):
    return {f.rule_id for f in scan(parse_text(text))}


def test_detects_known_bad_template():
    assert {"S3-004", "SG-001", "RDS-003", "IAM-001", "EC2-001"} <= ids(CASE)


def test_short_form_intrinsics_parse():
    t = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Sub '${AWS::StackName}-b'\n"
    assert any(r.logical_id == "B" for r in parse_text(t))


def test_port_443_open_is_not_a_finding():
    t = ("Resources:\n  S:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      GroupDescription: x\n"
         "      SecurityGroupIngress:\n        - {IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0}\n")
    assert "SG-001" not in ids(t)


def test_dlq_itself_is_not_flagged():
    t = json.dumps({"Resources": {
        "Dlq": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Q": {"Type": "AWS::SQS::Queue", "Properties": {"RedrivePolicy": {
            "deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]}, "maxReceiveCount": 3}}}}})
    assert "SQS-001" not in ids(t)


def test_terraform_plan_is_supported():
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
        {"address": "aws_db_instance.main", "type": "aws_db_instance",
         "values": {"storage_encrypted": False, "multi_az": False, "publicly_accessible": True,
                    "backup_retention_period": 0}}]}}}
    assert {"RDS-001", "RDS-002", "RDS-003"} <= ids(json.dumps(plan))


def test_patch_resolves_fixable_findings_and_is_verified():
    findings = scan(parse_text(CASE))
    v = patcher.verify_fixes(CASE, patcher.patch_template(CASE, findings))
    assert v["findings_after"] < v["findings_before"]
    assert "RDS-003::AppDb" in v["resolved"]
    assert "IAM-001::AppRole" in v["remaining"]  # needs human/LLM judgement: no safe automatic patch


def test_cost_savings_positive_for_prev_gen():
    s = cost.savings(parse_text(CASE))
    assert s["saved_monthly_usd"] > 0


def test_tool_handler_routes_and_reports_errors():
    out = handler({"tool": "scan_template", "arguments": {"template": CASE}})
    assert out["finding_count"] >= 10
    assert "error" in handler({"tool": "nope"})
    assert "missing required argument" in handler({"tool": "scan_template", "arguments": {}})["error"]


@pytest.mark.parametrize("bench,min_f1", [("benchmark/generated", 0.99), ("benchmark/hard", 0.99)])
def test_benchmark_quality_gate(bench, min_f1):
    if not (ROOT / bench / "labels.json").exists():
        pytest.skip("run benchmark/generate.py first")
    assert evaluate(ROOT / bench)["overall"]["f1"] >= min_f1
