"""Data models for scan results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    category: str
    severity: Severity
    description: str
    evidence: str = ""


@dataclass
class ScanResult:
    image_path: str
    findings: list[Finding] = field(default_factory=list)
    extracted_text: str = ""
    error: str = ""

    @property
    def clean(self) -> bool:
        """True only if the scan completed without error and produced no findings."""
        return not self.findings and not self.error

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
