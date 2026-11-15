"""Unit tests run against moto's in-memory AWS - no real account needed."""
import os

import boto3
import pytest
from moto import mock_aws

from cloudguard.checks import check_cloudtrail, check_iam, check_rds, check_s3, check_security_groups
from cloudguard.models import Finding, ScanResult, Severity
from cloudguard.scanner import scan

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws():
    os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                      AWS_SESSION_TOKEN="testing", AWS_DEFAULT_REGION=REGION,
                      MOTO_IAM_LOAD_MANAGED_POLICIES="true")
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def ids(findings):
    return {f.check_id for f in findings}


def test_public_bucket_is_critical(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="leaky")
    s3.put_bucket_acl(Bucket="leaky", ACL="public-read")
    findings, scanned = check_s3(aws, REGION)
    assert scanned == 1
    assert {"S3-001", "S3-002", "S3-003"} <= ids(findings)
    assert next(f for f in findings if f.check_id == "S3-002").severity is Severity.CRITICAL


def test_locked_down_bucket_passes(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="safe")
    s3.put_public_access_block(Bucket="safe", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket="safe", VersioningConfiguration={"Status": "Enabled"})
    findings, _ = check_s3(aws, REGION)
    assert findings == []


def test_ssh_open_to_world_flagged(aws):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings, _ = check_security_groups(aws, REGION)
    ssh = [f for f in findings if f.resource == sg]
    assert len(ssh) == 1 and ssh[0].severity is Severity.CRITICAL


def test_https_and_private_ssh_not_flagged(aws):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ok", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    findings, _ = check_security_groups(aws, REGION)
    assert not [f for f in findings if f.resource == sg]


def test_iam_user_without_mfa_and_admin(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Pw-123456789!")
    iam.attach_user_policy(UserName="bob", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    findings, _ = check_iam(aws, REGION)
    assert {"IAM-001", "IAM-003", "IAM-004"} <= ids(findings)


def test_strong_password_policy_passes(aws):
    aws.client("iam").update_account_password_policy(MinimumPasswordLength=16)
    findings, _ = check_iam(aws, REGION)
    assert "IAM-004" not in ids(findings)


def test_missing_cloudtrail_is_critical(aws):
    findings, _ = check_cloudtrail(aws, REGION)
    assert ids(findings) == {"LOG-001"}


def test_public_unencrypted_rds(aws):
    aws.client("rds").create_db_instance(
        DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="u", MasterUserPassword="p" * 10, AllocatedStorage=20,
        PubliclyAccessible=True, StorageEncrypted=False)
    findings, scanned = check_rds(aws, REGION)
    assert scanned == 1 and ids(findings) == {"RDS-001", "RDS-002"}


def test_full_scan_runs_all_checks(aws):
    result = scan([REGION], session=aws)
    assert result.checks_run >= 6
    assert result.errors == []
    assert 0 <= result.score <= 100


def test_score_and_grade():
    r = ScanResult(account_id="1", regions=[REGION])
    assert (r.score, r.grade) == (100, "A")
    r.findings = [Finding("X", "t", "S3", "r", REGION, Severity.CRITICAL, "d", "fix")] * 3
    assert (r.score, r.grade) == (70, "C")
