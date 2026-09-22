"""Data models for scan results."""

from dataclasses import dataclass, field
from enum import Enum


class DetectorError(Exception):
    """Raised by a check that could not complete.

    Every detector must either return its findings or raise this; a scan that
    records a detector failure is incomplete and can never be reported clean.
    """


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
    frame: int | None = None  # set for multi-frame images (GIF/TIFF/WebP)


@dataclass
class ScanResult:
    image_path: str
    findings: list[Finding] = field(default_factory=list)
    extracted_text: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def error(self) -> str:
        """All recorded failures joined into one string (empty when complete)."""
        return "; ".join(self.errors)

    @property
    def complete(self) -> bool:
        """True if every check ran to completion on every frame."""
        return not self.errors

    @property
    def clean(self) -> bool:
        """True only if the scan completed without error and produced no findings."""
        return not self.findings and self.complete

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
