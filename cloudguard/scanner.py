"""Runs every registered check across the requested regions."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import checks  # noqa: F401  (import registers the checks)
from .checks import REGISTRY
from .models import ScanResult

log = logging.getLogger("cloudguard")


def scan(regions: List[str], profile: Optional[str] = None, session=None) -> ScanResult:
    session = session or boto3.Session(profile_name=profile)
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as e:
        raise SystemExit(f"Could not authenticate to AWS: {e}") from e

    result = ScanResult(account_id=account, regions=regions)

    # Global checks run once; regional checks run per region, in parallel.
    jobs = []
    for name, is_global, fn in REGISTRY:
        for region in ([regions[0]] if is_global else regions):
            jobs.append((name, region, fn))

    def run(job):
        name, region, fn = job
        log.info("Running %-40s [%s]", name, region)
        try:
            return fn(session, region), None
        except (ClientError, BotoCoreError) as e:
            return ([], 0), f"{name} [{region}]: {e}"

    with ThreadPoolExecutor(max_workers=8) as pool:
        for (findings, scanned), err in pool.map(run, jobs):
            result.checks_run += 1
            result.findings.extend(findings)
            result.resources_scanned += scanned
            if err:
                log.warning(err)
                result.errors.append(err)
    return result
