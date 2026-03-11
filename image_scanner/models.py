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
    clean: bool = True
    findings: list[Finding] = field(default_factory=list)
    extracted_text: str = ""
    error: str = ""

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.clean = False
