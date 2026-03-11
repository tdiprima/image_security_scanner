"""Format and emit scan reports."""

import json
import logging
from datetime import datetime, timezone

from image_scanner.models import ScanResult, Severity

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def to_dict(result: ScanResult) -> dict:
    return {
        "image_path": result.image_path,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "clean": result.clean,
        "error": result.error,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in sorted(result.findings, key=lambda f: _SEVERITY_ORDER[f.severity])
        ],
    }


def print_report(result: ScanResult, output_format: str = "text") -> None:
    """Print the scan report to stdout in text or JSON format."""
    if output_format == "json":
        print(json.dumps(to_dict(result), indent=2))
        return

    status = "CLEAN" if result.clean else "FLAGGED"
    print("\n" + "=" * 60)
    print("  Image Security Scan Report")
    print(f"  File   : {result.image_path}")
    print(f"  Status : {status}")
    print("=" * 60)

    if result.error:
        print(f"  ERROR  : {result.error}")

    if result.clean:
        print("  No issues detected.\n")
        return

    sorted_findings = sorted(result.findings, key=lambda f: _SEVERITY_ORDER[f.severity])
    for finding in sorted_findings:
        print(f"\n  [{finding.severity.value.upper()}] {finding.category}")
        print(f"    Description : {finding.description}")
        if finding.evidence:
            print(f"    Evidence    : {finding.evidence}")

    print(f"\n  Total findings: {len(result.findings)}")
    print(f"{'=' * 60}\n")


def log_result(result: ScanResult) -> None:
    """Emit structured log entry for the scan result."""
    logger.info({
        "event": "scan_complete",
        "image_path": result.image_path,
        "clean": result.clean,
        "finding_count": len(result.findings),
        "severities": [f.severity.value for f in result.findings],
        "error": result.error or None,
    })
