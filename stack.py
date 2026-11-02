from aws_cdk import (
    CfnOutput, Duration, RemovalPolicy, Stack,
    aws_apigateway as apigw,
    aws_bedrock as bedrock,
    aws_bedrockagentcore as agentcore,
    aws_budgets as budgets,
    aws_cloudwatch as cw,
    aws_cognito as cognito,
    aws_dynamodb as ddb,
    aws_ecr_assets as ecr_assets,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as _lambda,
    aws_lambda_event_sources as sources,
    aws_logs as logs,
    aws_s3 as s3,
    aws_sqs as sqs,
)
from constructs import Construct

SDT = agentcore.SchemaDefinitionType


def _obj(props, required=()):
    return agentcore.SchemaDefinition(type=SDT.OBJECT, properties=props, required=list(required))


def _str(desc):
    return agentcore.SchemaDefinition(type=SDT.STRING, description=desc)


class ArchGuardStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, alert_email: str, monthly_budget_usd: float, **kw):
        super().__init__(scope, cid, **kw)

        # ------------------------------------------------------------------ security foundations
        key = kms.Key(self, "DataKey", enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)

        bucket = s3.Bucket(
            self, "Reports", encryption=s3.BucketEncryption.KMS, encryption_key=key, enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, versioned=True,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(90),
                                              noncurrent_version_expiration=Duration.days(7))],
            removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True,
        )

        jobs = ddb.Table(
            self, "Jobs", partition_key=ddb.Attribute(name="job_id", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST, time_to_live_attribute="ttl",
            point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(point_in_time_recovery_enabled=True),
            encryption=ddb.TableEncryption.CUSTOMER_MANAGED, encryption_key=key,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ------------------------------------------------------------------ auth
        pool = cognito.UserPool(
            self, "Users", self_sign_up_enabled=False, sign_in_aliases=cognito.SignInAliases(email=True),
            password_policy=cognito.PasswordPolicy(min_length=12, require_symbols=True, require_digits=True,
                                                   require_lowercase=True, require_uppercase=True),
            mfa=cognito.Mfa.OPTIONAL, mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            removal_policy=RemovalPolicy.DESTROY,
        )
        client = pool.add_client("Web", auth_flows=cognito.AuthFlow(user_srp=True),
                                 access_token_validity=Duration.hours(1), generate_secret=False)

        # ------------------------------------------------------------------ guardrail
        guardrail = bedrock.CfnGuardrail(
            self, "Guardrail", name="archguard-guardrail",
            blocked_input_messaging="Input blocked by ArchGuard guardrail.",
            blocked_outputs_messaging="Output blocked by ArchGuard guardrail.",
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                pii_entities_config=[
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type=t, action="ANONYMIZE", input_action="ANONYMIZE",
                                                                  output_action="ANONYMIZE")
                    for t in ("EMAIL", "PHONE", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD")]),
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(filters_config=[
                bedrock.CfnGuardrail.ContentFilterConfigProperty(type="PROMPT_ATTACK", input_strength="HIGH",
                                                                  output_strength="NONE")]),
        )
        guardrail_version = bedrock.CfnGuardrailVersion(self, "GuardrailV1", guardrail_identifier=guardrail.attr_guardrail_id)

        # ------------------------------------------------------------------ tool Lambda (behind Gateway)
        code = _lambda.Code.from_asset("build/lambda")
        tools_fn = _lambda.Function(
            self, "ToolsFn", runtime=_lambda.Runtime.PYTHON_3_13, architecture=_lambda.Architecture.ARM_64,
            handler="archguard.tools_handler.handler", code=code, timeout=Duration.seconds(30), memory_size=512,
            tracing=_lambda.Tracing.ACTIVE, log_retention=logs.RetentionDays.ONE_MONTH,
        )

        # ------------------------------------------------------------------ AgentCore Gateway (MCP)
        gateway = agentcore.Gateway(
            self, "Gateway", gateway_name="archguard-tools",
            description="MCP tools: IaC scanning, cost estimation, remediation",
            authorizer_configuration=agentcore.GatewayAuthorizer.using_cognito(user_pool=pool, allowed_clients=[client]),
            protocol_configuration=agentcore.GatewayProtocol.mcp(search_type=agentcore.McpGatewaySearchType.SEMANTIC),
        )
        tmpl = _str("Full text of the CloudFormation / CDK-synth / Terraform-plan document")
        gateway.add_lambda_target(
            "Tools", gateway_target_name="archguard", lambda_function=tools_fn,
            description="Deterministic Well-Architected scanner",
            tool_schema=agentcore.ToolSchema.from_inline([
                agentcore.ToolDefinition(name="scan_template", description="Scan IaC and return Well-Architected findings",
                                         input_schema=_obj({"template": tmpl}, ["template"])),
                agentcore.ToolDefinition(name="estimate_cost", description="Estimate monthly cost before/after optimization",
                                         input_schema=_obj({"template": tmpl}, ["template"])),
                agentcore.ToolDefinition(name="apply_fixes", description="Apply deterministic remediations and verify by re-scan",
                                         input_schema=_obj({"template": tmpl}, ["template"])),
                agentcore.ToolDefinition(name="list_rules", description="List all rule IDs",
                                         input_schema=_obj({})),
            ]),
        )

        # ------------------------------------------------------------------ AgentCore Runtime (agents)
        runtime = agentcore.Runtime(
            self, "Runtime", runtime_name="archguard_reviewer",
            agent_runtime_artifact=agentcore.AgentRuntimeArtifact.from_asset(
                ".", file="agents/Dockerfile", platform=ecr_assets.Platform.LINUX_ARM64,
                exclude=["build", "cdk.out", ".git", "benchmark", "tests", "node_modules", "infra"]),
            description="Supervisor + Well-Architected specialist agents",
            network_configuration=agentcore.RuntimeNetworkConfiguration.using_public_network(),
            lifecycle_configuration=agentcore.LifecycleConfiguration(
                idle_runtime_session_timeout=Duration.minutes(10), max_lifetime=Duration.hours(1)),
            environment_variables={
                "AWS_REGION": self.region,
                "ARCHGUARD_GUARDRAIL_ID": guardrail.attr_guardrail_id,
                "ARCHGUARD_GUARDRAIL_VERSION": guardrail_version.attr_version,
            },
            tracing_enabled=True,
        )
        runtime.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:ApplyGuardrail"],
            resources=["*"]))  # inference profiles span regions; scope down per account policy in prod

        # ------------------------------------------------------------------ async pipeline
        dlq = sqs.Queue(self, "Dlq", encryption=sqs.QueueEncryption.KMS, encryption_master_key=key,
                        retention_period=Duration.days(14))
        queue = sqs.Queue(self, "Queue", encryption=sqs.QueueEncryption.KMS, encryption_master_key=key,
                          visibility_timeout=Duration.minutes(16),
                          dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=3, queue=dlq))

        env = {"JOBS_TABLE": jobs.table_name, "REPORTS_BUCKET": bucket.bucket_name, "QUEUE_URL": queue.queue_url}
        api_fn = _lambda.Function(
            self, "ApiFn", runtime=_lambda.Runtime.PYTHON_3_13, architecture=_lambda.Architecture.ARM_64,
            handler="submit.handler", code=code, timeout=Duration.seconds(15), environment=env,
            tracing=_lambda.Tracing.ACTIVE, log_retention=logs.RetentionDays.ONE_MONTH)
        worker_fn = _lambda.Function(
            self, "WorkerFn", runtime=_lambda.Runtime.PYTHON_3_13, architecture=_lambda.Architecture.ARM_64,
            handler="worker.handler", code=code, timeout=Duration.minutes(15), memory_size=512,
            environment={**env, "RUNTIME_ARN": runtime.agent_runtime_arn}, tracing=_lambda.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_MONTH, reserved_concurrent_executions=5)  # caps Bedrock spend
        worker_fn.add_event_source(sources.SqsEventSource(queue, batch_size=1))

        jobs.grant_read_write_data(api_fn); jobs.grant_read_write_data(worker_fn)
        bucket.grant_read_write(api_fn); bucket.grant_read_write(worker_fn)
        queue.grant_send_messages(api_fn)
        runtime.grant_invoke_runtime(worker_fn)

        # ------------------------------------------------------------------ API
        api = apigw.RestApi(
            self, "Api", rest_api_name="archguard",
            deploy_options=apigw.StageOptions(stage_name="v1", tracing_enabled=True, throttling_rate_limit=5,
                                              throttling_burst_limit=10, metrics_enabled=True))
        auth = apigw.CognitoUserPoolsAuthorizer(self, "Auth", cognito_user_pools=[pool])
        integ = apigw.LambdaIntegration(api_fn)
        reviews = api.root.add_resource("reviews")
        reviews.add_method("POST", integ, authorizer=auth, authorization_type=apigw.AuthorizationType.COGNITO)
        reviews.add_resource("{id}").add_method("GET", integ, authorizer=auth,
                                                authorization_type=apigw.AuthorizationType.COGNITO)

        # ------------------------------------------------------------------ observability + cost guard
        dash = cw.Dashboard(self, "Dash", dashboard_name="ArchGuard")
        dash.add_widgets(
            cw.GraphWidget(title="Worker errors / throttles", left=[worker_fn.metric_errors(), worker_fn.metric_throttles()]),
            cw.GraphWidget(title="Agent runtime invocations", left=[runtime.metric_invocations(), runtime.metric_total_errors()]),
            cw.GraphWidget(title="Review latency p95 (ms)", left=[runtime.metric_latency()]),
            cw.GraphWidget(title="DLQ depth", left=[dlq.metric_approximate_number_of_messages_visible()]),
        )
        cw.Alarm(self, "DlqAlarm", metric=dlq.metric_approximate_number_of_messages_visible(), threshold=1,
                 evaluation_periods=1, alarm_description="Reviews are failing permanently")

        budgets.CfnBudget(
            self, "Budget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                budget_type="COST", time_unit="MONTHLY", budget_name="archguard-monthly",
                budget_limit=budgets.CfnBudget.SpendProperty(amount=monthly_budget_usd, unit="USD")),
            notifications_with_subscribers=[budgets.CfnBudget.NotificationWithSubscribersProperty(
                notification=budgets.CfnBudget.NotificationProperty(
                    notification_type="ACTUAL", comparison_operator="GREATER_THAN", threshold=t, threshold_type="PERCENTAGE"),
                subscribers=[budgets.CfnBudget.SubscriberProperty(subscription_type="EMAIL", address=alert_email)])
                for t in (50, 80, 100)])

        CfnOutput(self, "ApiUrl", value=api.url)
        CfnOutput(self, "UserPoolId", value=pool.user_pool_id)
        CfnOutput(self, "UserPoolClientId", value=client.user_pool_client_id)
        CfnOutput(self, "GatewayUrl", value=gateway.gateway_url or "")
        CfnOutput(self, "RuntimeArn", value=runtime.agent_runtime_arn)
