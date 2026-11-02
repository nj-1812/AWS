"""SQS worker: run the AgentCore Runtime review, persist report to S3, update job status.
Idempotent: a redelivered message for a COMPLETED job is a no-op. Failures raise -> SQS retry -> DLQ."""
import json
import os
import time

import boto3

ddb = boto3.resource("dynamodb").Table(os.environ["JOBS_TABLE"])
s3 = boto3.client("s3")
agentcore = boto3.client("bedrock-agentcore")
BUCKET = os.environ["REPORTS_BUCKET"]


def handler(event, _ctx):
    for record in event["Records"]:
        job_id = json.loads(record["body"])["job_id"]
        job = ddb.get_item(Key={"job_id": job_id}).get("Item")
        if not job or job["status"] == "COMPLETED":
            continue
        ddb.update_item(Key={"job_id": job_id}, UpdateExpression="SET #s=:s, started=:t",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={":s": "RUNNING", ":t": int(time.time())})
        template = s3.get_object(Bucket=BUCKET, Key=job["input_key"])["Body"].read().decode()
        t0 = time.time()
        try:
            resp = agentcore.invoke_agent_runtime(
                agentRuntimeArn=os.environ["RUNTIME_ARN"],
                runtimeSessionId=f"{job_id}-{'0' * 33}"[:40],  # session ids must be >= 33 chars
                payload=json.dumps({"template": template, "deep": job.get("deep", False)}).encode(),
                contentType="application/json", accept="application/json")
            result = json.loads(resp["response"].read())
        except Exception as e:
            ddb.update_item(Key={"job_id": job_id}, UpdateExpression="SET #s=:s, err=:e",
                            ExpressionAttributeNames={"#s": "status"},
                            ExpressionAttributeValues={":s": "FAILED", ":e": str(e)[:500]})
            raise
        key = f"reports/{job['user']}/{job_id}.md"
        s3.put_object(Bucket=BUCKET, Key=key, Body=result.get("report_markdown", "").encode(),
                      ServerSideEncryption="aws:kms", ContentType="text/markdown")
        ddb.update_item(Key={"job_id": job_id},
                        UpdateExpression="SET #s=:s, report_key=:k, latency_s=:l, report_preview=:p",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={":s": "COMPLETED", ":k": key,
                                                   ":l": int(time.time() - t0),
                                                   ":p": result.get("report_markdown", "")[:2000]})
