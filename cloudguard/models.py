"""Core data models for CloudGuard findings."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        """Points deducted from the security score for each failed check."""
        return {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}[self.value]

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[self.value]


@dataclass
class Finding:
    check_id: str          # e.g. "S3-001"
    title: str             # short human-readable name of the check
    service: str           # AWS service: S3, EC2, IAM, ...
    resource: str          # ARN / ID of the affected resource
    region: str
    severity: Severity
    description: str       # what is wrong and why it matters
    remediation: str       # how to fix it
    cis: str = ""          # CIS AWS Foundations Benchmark control, if any

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    account_id: str
    regions: List[str]
    findings: List[Finding] = field(default_factory=list)
    checks_run: int = 0
    resources_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def score(self) -> int:
        """0-100 posture score. Starts at 100 and deducts per finding (floor 0)."""
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"

    def counts(self) -> dict:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.service, f.check_id))

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "regions": self.regions,
            "started_at": self.started_at,
            "score": self.score,
            "grade": self.grade,
            "checks_run": self.checks_run,
            "resources_scanned": self.resources_scanned,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
