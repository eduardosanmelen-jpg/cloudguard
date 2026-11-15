"""Demo mode: builds a deliberately misconfigured AWS account inside moto
(an in-memory AWS mock) and scans it with the real checks. No AWS account
or credentials needed, and nothing touches real AWS.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import boto3

from .scanner import scan


def build_vulnerable_account(region: str) -> None:
    s3 = boto3.client("s3", region_name=region)
    # public, unversioned bucket
    s3.create_bucket(Bucket="acme-customer-exports")
    s3.put_bucket_acl(Bucket="acme-customer-exports", ACL="public-read")
    # properly locked-down bucket (should pass S3-001/002)
    s3.create_bucket(Bucket="acme-secure-backups")
    s3.put_public_access_block(Bucket="acme-secure-backups", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket="acme-secure-backups", VersioningConfiguration={"Status": "Enabled"})

    ec2 = boto3.client("ec2", region_name=region)
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    for name, port in (("bastion-ssh", 22), ("win-jumpbox", 3389), ("legacy-mysql", 3306)):
        sg = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ok = ec2.create_security_group(GroupName="web-https", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ok, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    iam = boto3.client("iam", region_name=region)
    iam.create_user(UserName="jsmith")
    iam.create_login_profile(UserName="jsmith", Password="Temp-Password-123!")
    iam.attach_user_policy(UserName="jsmith", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_user(UserName="ci-deploy-bot")
    iam.create_access_key(UserName="ci-deploy-bot")

    rds = boto3.client("rds", region_name=region)
    rds.create_db_instance(DBInstanceIdentifier="orders-db", DBInstanceClass="db.t3.micro",
                           Engine="postgres", MasterUsername="admin", MasterUserPassword="not-a-real-pass",
                           AllocatedStorage=20, PubliclyAccessible=True, StorageEncrypted=False)


def run_demo(region: str = "us-east-1"):
    from moto import mock_aws

    # Fake credentials so boto3 never looks for (or uses) real ones.
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": region,
                 "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        os.environ[k] = v
    os.environ.pop("AWS_PROFILE", None)

    with mock_aws():
        build_vulnerable_account(region)
        result = scan([region], session=boto3.Session(region_name=region))

    # moto can't backdate access keys, so simulate one stale key for the demo.
    stale_created = datetime.now(timezone.utc) - timedelta(days=214)
    from .models import Finding, Severity
    result.findings.append(Finding(
        "IAM-002", "Access key older than 90 days", "IAM",
        f"arn:aws:iam::{result.account_id}:user/ci-deploy-bot (AKIADEMOSTALEKEY0001)", "global",
        Severity.MEDIUM,
        f"Access key AKIADEMOSTALEKEY0001 for 'ci-deploy-bot' was created {stale_created:%Y-%m-%d} "
        "(214 days ago). Long-lived keys are frequently leaked in code repos and laptops.",
        "Rotate the key (create new, update apps, deactivate old) or move to IAM roles / SSO.",
        "CIS 1.14"))
    return result
