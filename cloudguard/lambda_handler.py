"""AWS Lambda entry point. Deployed by terraform/ to run on a schedule:
scans the account, saves HTML + JSON reports to S3, and sends an SNS alert
when CRITICAL or HIGH findings exist.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import boto3

from .report import to_html, to_json
from .scanner import scan


def handler(event, context):
    regions = [r.strip() for r in os.environ.get("SCAN_REGIONS", os.environ["AWS_REGION"]).split(",")]
    bucket = os.environ["REPORT_BUCKET"]
    topic = os.environ.get("ALERT_TOPIC_ARN")

    result = scan(regions)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    s3 = boto3.client("s3")
    for key, body, ctype in ((f"reports/{stamp}.html", to_html(result), "text/html"),
                             (f"reports/{stamp}.json", to_json(result), "application/json"),
                             ("reports/latest.html", to_html(result), "text/html")):
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode(), ContentType=ctype)

    counts = result.counts()
    if topic and (counts["CRITICAL"] or counts["HIGH"]):
        top = "\n".join(f"- [{f.severity.value}] {f.title}: {f.resource}"
                        for f in result.sorted_findings()[:10])
        boto3.client("sns").publish(
            TopicArn=topic,
            Subject=f"CloudGuard: score {result.score}/100 - {counts['CRITICAL']} critical, {counts['HIGH']} high",
            Message=f"Account {result.account_id}\n\n{top}\n\nFull report: s3://{bucket}/reports/{stamp}.html")

    return {"score": result.score, "summary": counts, "report": f"s3://{bucket}/reports/{stamp}.html"}
