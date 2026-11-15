"""Security checks. Each check takes a boto3 Session + region and returns
(findings, resources_scanned). Checks are registered with @check so the
scanner discovers them automatically - adding a new check is one function.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, List, Tuple

from botocore.exceptions import ClientError

from .models import Finding, Severity

CheckFn = Callable[..., Tuple[List[Finding], int]]
REGISTRY: List[Tuple[str, bool, CheckFn]] = []  # (name, is_global, fn)

RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
KEY_MAX_AGE_DAYS = 90


def check(name: str, global_service: bool = False):
    """Register a check. Global checks (IAM, S3) run once, not per region."""
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY.append((name, global_service, fn))
        return fn
    return deco


# ---------------------------------------------------------------- S3
@check("S3 public access & encryption", global_service=True)
def check_s3(session, region: str):
    s3 = session.client("s3", region_name=region)
    buckets = s3.list_buckets().get("Buckets", [])
    findings: List[Finding] = []
    for b in buckets:
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"

        # S3-001: Block Public Access not fully enabled
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(cfg.get(k) for k in
                                ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except ClientError:
            fully_blocked = False
        if not fully_blocked:
            findings.append(Finding(
                "S3-001", "S3 Block Public Access disabled", "S3", arn, "global", Severity.HIGH,
                f"Bucket '{name}' does not have all four Block Public Access settings enabled, so a "
                "single bad ACL or policy change could expose its data to the internet.",
                f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "CIS 2.1.4"))

        # S3-002: ACL grants access to AllUsers / AuthenticatedUsers
        try:
            grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
            public = [g for g in grants if "AllUsers" in g.get("Grantee", {}).get("URI", "")
                      or "AuthenticatedUsers" in g.get("Grantee", {}).get("URI", "")]
        except ClientError:
            public = []
        if public:
            findings.append(Finding(
                "S3-002", "S3 bucket publicly accessible via ACL", "S3", arn, "global", Severity.CRITICAL,
                f"Bucket '{name}' has an ACL granting {public[0]['Permission']} to everyone on the internet. "
                "Public buckets are one of the most common causes of cloud data breaches.",
                f"aws s3api put-bucket-acl --bucket {name} --acl private",
                "CIS 2.1.4"))

        # S3-003: Versioning disabled (ransomware / accidental delete protection)
        try:
            status = s3.get_bucket_versioning(Bucket=name).get("Status")
        except ClientError:
            status = None
        if status != "Enabled":
            findings.append(Finding(
                "S3-003", "S3 versioning disabled", "S3", arn, "global", Severity.LOW,
                f"Bucket '{name}' does not keep object versions, so deleted or overwritten "
                "(e.g. ransomware-encrypted) objects cannot be recovered.",
                f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled"))
    return findings, len(buckets)


# ---------------------------------------------------------------- EC2
@check("EC2 security groups open to the internet")
def check_security_groups(session, region: str):
    ec2 = session.client("ec2", region_name=region)
    groups = ec2.describe_security_groups().get("SecurityGroups", [])
    findings: List[Finding] = []
    for sg in groups:
        for perm in sg.get("IpPermissions", []):
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not (open_v4 or open_v6):
                continue
            proto = perm.get("IpProtocol")
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            if proto == "-1":
                exposed = {0: "ALL TRAFFIC"}
            else:
                exposed = {p: n for p, n in RISKY_PORTS.items() if lo <= p <= hi}
            for port, svc in exposed.items():
                admin = svc in ("SSH", "RDP", "ALL TRAFFIC")
                findings.append(Finding(
                    "EC2-001", f"{svc} open to the internet", "EC2", sg["GroupId"], region,
                    Severity.CRITICAL if admin else Severity.HIGH,
                    f"Security group '{sg.get('GroupName')}' ({sg['GroupId']}) allows {svc}"
                    f"{'' if port == 0 else f' (port {port})'} from 0.0.0.0/0. Internet-exposed "
                    "admin/database ports are constantly brute-forced by automated bots.",
                    "Restrict the source to your office/VPN CIDR, or remove the rule and use "
                    "AWS Systems Manager Session Manager for shell access.",
                    "CIS 5.2" if admin else ""))
    return findings, len(groups)


@check("EBS default encryption")
def check_ebs_encryption(session, region: str):
    ec2 = session.client("ec2", region_name=region)
    enabled = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
    if enabled:
        return [], 1
    return [Finding(
        "EC2-002", "EBS encryption-by-default disabled", "EC2", f"ebs-default/{region}", region,
        Severity.MEDIUM,
        f"New EBS volumes in {region} are not encrypted automatically, so disk snapshots "
        "could leak data if shared or copied.",
        f"aws ec2 enable-ebs-encryption-by-default --region {region}",
        "CIS 2.2.1")], 1


# ---------------------------------------------------------------- IAM
@check("IAM users, MFA & access keys", global_service=True)
def check_iam(session, region: str):
    iam = session.client("iam", region_name=region)
    findings: List[Finding] = []
    users = []
    for page in iam.get_paginator("list_users").paginate():
        users.extend(page["Users"])
    now = datetime.now(timezone.utc)

    for u in users:
        name, arn = u["UserName"], u["Arn"]
        has_password = True
        try:
            iam.get_login_profile(UserName=name)
        except ClientError:
            has_password = False

        if has_password and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            findings.append(Finding(
                "IAM-001", "Console user without MFA", "IAM", arn, "global", Severity.HIGH,
                f"User '{name}' can sign in to the AWS console with only a password. "
                "A phished or reused password gives an attacker full access.",
                "Enable a virtual or hardware MFA device for this user and enforce MFA with an IAM policy.",
                "CIS 1.10"))

        for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            age = (now - key["CreateDate"]).days
            if key["Status"] == "Active" and age > KEY_MAX_AGE_DAYS:
                findings.append(Finding(
                    "IAM-002", "Access key older than 90 days", "IAM", f"{arn} ({key['AccessKeyId']})",
                    "global", Severity.MEDIUM,
                    f"Access key {key['AccessKeyId']} for '{name}' is {age} days old. Long-lived keys "
                    "are frequently leaked in code repos and laptops.",
                    "Rotate the key (create new, update apps, deactivate old) or move to IAM roles / SSO.",
                    "CIS 1.14"))

        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        if any(p["PolicyArn"].endswith(":policy/AdministratorAccess") for p in attached):
            findings.append(Finding(
                "IAM-003", "AdministratorAccess attached directly to user", "IAM", arn, "global",
                Severity.MEDIUM,
                f"User '{name}' has full admin rights attached directly. This breaks least privilege "
                "and makes access hard to audit.",
                "Grant permissions through IAM groups or roles scoped to the job, and remove the direct attachment.",
                "CIS 1.15"))

    # IAM-004: account password policy
    try:
        pol = iam.get_account_password_policy()["PasswordPolicy"]
        weak = pol.get("MinimumPasswordLength", 0) < 14
    except ClientError:
        weak = True
    if weak:
        findings.append(Finding(
            "IAM-004", "Weak or missing account password policy", "IAM", "account-password-policy",
            "global", Severity.MEDIUM,
            "The account password policy is missing or allows passwords shorter than 14 characters.",
            "aws iam update-account-password-policy --minimum-password-length 14 "
            "--require-symbols --require-numbers --require-uppercase-characters "
            "--require-lowercase-characters --password-reuse-prevention 24",
            "CIS 1.8"))
    return findings, len(users) + 1


# ---------------------------------------------------------------- Logging
@check("CloudTrail audit logging")
def check_cloudtrail(session, region: str):
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    logging = False
    for t in trails:
        try:
            if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                logging = True
                break
        except ClientError:
            continue
    if logging:
        return [], len(trails)
    return [Finding(
        "LOG-001", "CloudTrail not logging", "CloudTrail", f"cloudtrail/{region}", region,
        Severity.CRITICAL,
        f"No active CloudTrail trail covers {region}. Without an audit log there is no record of "
        "who did what - incident response becomes guesswork.",
        "Create a multi-region trail: aws cloudtrail create-trail --name org-trail "
        "--s3-bucket-name <log-bucket> --is-multi-region-trail && aws cloudtrail start-logging --name org-trail",
        "CIS 3.1")], max(1, len(trails))


# ---------------------------------------------------------------- RDS
@check("RDS public & unencrypted databases")
def check_rds(session, region: str):
    rds = session.client("rds", region_name=region)
    dbs = rds.describe_db_instances().get("DBInstances", [])
    findings: List[Finding] = []
    for db in dbs:
        arn, dbid = db["DBInstanceArn"], db["DBInstanceIdentifier"]
        if db.get("PubliclyAccessible"):
            findings.append(Finding(
                "RDS-001", "RDS instance publicly accessible", "RDS", arn, region, Severity.HIGH,
                f"Database '{dbid}' has a public endpoint reachable from the internet.",
                f"aws rds modify-db-instance --db-instance-identifier {dbid} --no-publicly-accessible --apply-immediately",
                "CIS 2.3.3"))
        if not db.get("StorageEncrypted"):
            findings.append(Finding(
                "RDS-002", "RDS storage not encrypted", "RDS", arn, region, Severity.MEDIUM,
                f"Database '{dbid}' stores data unencrypted at rest.",
                "Snapshot the DB, copy the snapshot with --kms-key-id, and restore from the encrypted copy.",
                "CIS 2.3.1"))
    return findings, len(dbs)
