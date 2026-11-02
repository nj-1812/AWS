"""POST /reviews -> validate, store job (QUEUED), enqueue to SQS. GET /reviews/{id} -> job + report."""
import json
import os
import time
import uuid

import boto3

ddb = boto3.resource("dynamodb").Table(os.environ["JOBS_TABLE"])
sqs = boto3.client("sqs")
s3 = boto3.client("s3")
MAX_BYTES = 512_000


def _resp(code, body):
    return {"statusCode": code, "headers": {"content-type": "application/json"}, "body": json.dumps(body, default=str)}


def _user(event):
    return event["requestContext"]["authorizer"]["claims"]["sub"]


def handler(event, _ctx):
    user = _user(event)
    if event["httpMethod"] == "POST":
        body = json.loads(event.get("body") or "{}")
        template = body.get("template", "")
        if not template.strip() or len(template.encode()) > MAX_BYTES:
            return _resp(400, {"error": "template required and must be < 500KB"})
        job_id = str(uuid.uuid4())
        key = f"inputs/{user}/{job_id}.txt"
        s3.put_object(Bucket=os.environ["REPORTS_BUCKET"], Key=key, Body=template.encode(), ServerSideEncryption="aws:kms")
        ddb.put_item(Item={"job_id": job_id, "user": user, "status": "QUEUED", "created": int(time.time()),
                           "input_key": key, "deep": bool(body.get("deep", False)),
                           "ttl": int(time.time()) + 30 * 86400})
        sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps({"job_id": job_id}))
        return _resp(202, {"job_id": job_id, "status": "QUEUED"})
    job_id = event["pathParameters"]["id"]
    item = ddb.get_item(Key={"job_id": job_id}).get("Item")
    if not item or item["user"] != user:  # tenant isolation: never reveal other users' jobs
        return _resp(404, {"error": "not found"})
    item.pop("input_key", None)
    return _resp(200, item)
