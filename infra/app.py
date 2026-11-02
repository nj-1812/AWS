#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stack import ArchGuardStack

app = cdk.App()
ArchGuardStack(
    app,
    "ArchGuard",
    alert_email=app.node.try_get_context("alert_email") or os.getenv("ALERT_EMAIL", "you@example.com"),
    supervisor_model=app.node.try_get_context("supervisor_model") or "global.anthropic.claude-sonnet-5-5",
    specialist_model=app.node.try_get_context("specialist_model") or "global.anthropic.claude-haiku-5-5",
    monthly_budget_usd=float(app.node.try_get_context("budget_usd") or 25),
    env=cdk.Environment(account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION", "us-east-1")),
)
app.synth()
