"""Generate a labelled benchmark of CloudFormation templates with seeded misconfigurations.

Ground truth comes from the *injection*, not from the scanner: each case starts from a hardened
baseline (every resource passes every rule) and a seeded RNG flips selected properties into known
bad states, recording the expected (rule_id, resource_id) pairs. Unflipped resources act as
negatives, so false positives are measurable.

    python benchmark/generate.py --n 40 --seed 7
"""

from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path

import yaml

BASELINE = {
    "DataBucket": {"Type": "AWS::S3::Bucket", "Properties": {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [
            {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
                                           "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
        "VersioningConfiguration": {"Status": "Enabled"}}},
    "WebSG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "web", "SecurityGroupIngress": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}]}},  # 443 is fine
    "AppDb": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceClass": "db.m5.large", "Engine": "mysql", "StorageEncrypted": True, "MultiAZ": True,
        "PubliclyAccessible": False, "BackupRetentionPeriod": 7}},
    "AppVol": {"Type": "AWS::EC2::Volume", "Properties": {
        "AvailabilityZone": "us-east-1a", "Size": 100, "VolumeType": "gp3", "Encrypted": True}},
    "AppServer": {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "m6g.large"}},
    "Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}},
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {"TracingConfig": {"Mode": "Active"}}},
    "WorkQueue": {"Type": "AWS::SQS::Queue", "Properties": {
        "RedrivePolicy": {"deadLetterTargetArn": "arn:aws:sqs:us-east-1:123456789012:dlq", "maxReceiveCount": 3}}},
    "AppRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{"PolicyName": "scoped", "PolicyDocument": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                                                "Resource": "arn:aws:s3:::my-bucket/*"}]}}]}},
}


def _set(path: str, key: str, value):
    def inject(props):
        props[key] = value
    return inject


def _drop(key):
    return lambda props: props.pop(key, None)


def _admin_policy(props):
    props["Policies"][0]["PolicyDocument"]["Statement"][0].update({"Action": "*", "Resource": "*"})


def _open_ssh(props):
    props["SecurityGroupIngress"].append({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"})


def _open_all(props):
    props["SecurityGroupIngress"].append({"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"})


def _pab_partial(props):
    props["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = False


# rule_id -> (resource, injector). The mapping states what a *human reviewer* would call a defect.
INJECTORS = {
    "S3-001": ("DataBucket", _drop("BucketEncryption")),
    "S3-002": ("DataBucket", _pab_partial),
    "S3-003": ("DataBucket", _set("", "VersioningConfiguration", {"Status": "Suspended"})),
    "S3-004": ("DataBucket", _set("", "AccessControl", "PublicRead")),
    "SG-001": ("WebSG", _open_ssh),
    "SG-002": ("WebSG", _open_all),
    "RDS-001": ("AppDb", _set("", "StorageEncrypted", False)),
    "RDS-002": ("AppDb", _set("", "MultiAZ", False)),
    "RDS-003": ("AppDb", _set("", "PubliclyAccessible", True)),
    "RDS-004": ("AppDb", _set("", "BackupRetentionPeriod", 1)),
    "IAM-001": ("AppRole", _admin_policy),
    "EBS-001": ("AppVol", _set("", "Encrypted", False)),
    "EBS-002": ("AppVol", _set("", "VolumeType", "gp2")),
    "EC2-001": ("AppServer", _set("", "InstanceType", "m4.large")),
    "DDB-001": ("Table", _set("", "PointInTimeRecoverySpecification", {"PointInTimeRecoveryEnabled": False})),
    "LAM-001": ("Fn", _drop("TracingConfig")),
    "SQS-001": ("WorkQueue", _drop("RedrivePolicy")),
}
# Injecting SG-002 also trivially opens ports but via protocol -1 (no port range), so only SG-002 is expected.
INCOMPATIBLE = {frozenset({"SG-001", "SG-002"})}  # keep labels unambiguous


def make_case(rng: random.Random):
    ids = list(INJECTORS)
    k = rng.randint(1, 7)
    chosen: list[str] = []
    for rid in rng.sample(ids, len(ids)):
        if len(chosen) == k:
            break
        if any(frozenset({rid, c}) in INCOMPATIBLE for c in chosen):
            continue
        chosen.append(rid)
    res = copy.deepcopy(BASELINE)
    for rid in chosen:
        name, inj = INJECTORS[rid]
        inj(res[name]["Properties"])
    template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": res}
    expected = sorted([rid, INJECTORS[rid][0]] for rid in chosen)
    return template, expected


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(Path(__file__).parent / "generated"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    labels = {}
    for i in range(args.n):
        tpl, exp = make_case(rng)
        name = f"case_{i:03d}.yaml"
        (out / name).write_text(yaml.safe_dump(tpl, sort_keys=False))
        labels[name] = exp
    (out / "labels.json").write_text(json.dumps(labels, indent=1))
    print(f"wrote {args.n} cases + labels.json to {out}")


if __name__ == "__main__":
    main()
