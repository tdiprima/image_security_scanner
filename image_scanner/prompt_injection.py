"""Detect prompt injection patterns in extracted text."""

import base64
import logging
import re

from image_scanner.models import Finding, Severity

logger = logging.getLogger(__name__)

# Ordered by severity — checked against lowercased, normalized text.
_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|above|your)\s+", "Instruction override attempt"),
    (r"forget\s+(everything|all|your\s+(previous|prior|training|instructions?))", "Memory wipe attempt"),
    (r"new\s+system\s+prompt", "System prompt replacement"),
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+image)", "Persona hijack attempt"),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(?:dan|jailbreak|evil|unrestricted)", "Jailbreak persona"),
    (r"\[system\]|\[inst\]|<\|system\|>|<<sys>>|<\|im_start\|>", "LLM control token injection"),
    (r"###\s*instruction|##\s*system|###\s*human|###\s*assistant", "Markdown prompt injection"),
]

_HIGH_PATTERNS: list[tuple[str, str]] = [
    (r"do\s+not\s+(follow|obey|respect)\s+(your\s+)?(rules?|guidelines?|instructions?)", "Rule bypass"),
    (r"(override|bypass|disable)\s+(safety|filter|content\s+polic)", "Safety bypass"),
    (r"pretend\s+(you\s+)?(are|have\s+no)\s+(a\s+)?(restrictions?|limits?|ethics?)", "Restriction removal"),
    (r"reveal\s+(your\s+)?(system\s+prompt|instructions?|secret)", "Prompt extraction"),
    (r"repeat\s+(after\s+me|the\s+following|everything\s+i\s+say)", "Repetition injection"),
    (r"translate\s+and\s+execute|execute\s+the\s+following", "Execution injection"),
]

_MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"you\s+must\s+(now\s+)?(always|never|only)", "Behavior constraint injection"),
    (r"from\s+now\s+on\s+you\s+(will|must|should|are)", "Persistent instruction injection"),
    (r"your\s+(true\s+)?(purpose|goal|mission|role)\s+is", "Role redefinition"),
    (r"(admin|developer|root|god)\s+mode", "Privilege escalation attempt"),
    (r"confidential|do\s+not\s+share|keep\s+(this\s+)?secret", "Secrecy instruction"),
]

# Unicode homoglyph ranges that may be used to evade text filters.
_HOMOGLYPH_PATTERN = re.compile(
    r"[\u0400-\u04FF\u1D00-\u1D7F\u2100-\u214F\uFB00-\uFB4F\uFF00-\uFFEF]"
)

# Invisible / zero-width characters used to hide content.
_INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]"
)


def _normalize(text: str) -> str:
    """Collapse whitespace and lowercase for pattern matching."""
    return re.sub(r"\s+", " ", text).lower()


def _check_base64_payloads(text: str) -> list[Finding]:
    """Decode any base64 blobs and recursively scan for injection patterns."""
    findings: list[Finding] = []
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
            if any(re.search(p, _normalize(decoded)) for p, _ in _CRITICAL_PATTERNS + _HIGH_PATTERNS):
                findings.append(Finding(
                    category="prompt_injection",
                    severity=Severity.CRITICAL,
                    description="Base64-encoded prompt injection payload",
                    evidence=f"token={token[:40]}… decoded={decoded[:80]}",
                ))
        except Exception:
            pass
    return findings


def scan_for_prompt_injection(text: str) -> list[Finding]:
    """Return all prompt injection findings from extracted text."""
    findings: list[Finding] = []
    if not text:
        return findings

    normalized = _normalize(text)
    logger.debug({"event": "prompt_injection_scan_start", "text_length": len(text)})

    for pattern, description in _CRITICAL_PATTERNS:
        match = re.search(pattern, normalized)
        if match:
            findings.append(Finding(
                category="prompt_injection",
                severity=Severity.CRITICAL,
                description=description,
                evidence=match.group(0),
            ))

    for pattern, description in _HIGH_PATTERNS:
        match = re.search(pattern, normalized)
        if match:
            findings.append(Finding(
                category="prompt_injection",
                severity=Severity.HIGH,
                description=description,
                evidence=match.group(0),
            ))

    for pattern, description in _MEDIUM_PATTERNS:
        match = re.search(pattern, normalized)
        if match:
            findings.append(Finding(
                category="prompt_injection",
                severity=Severity.MEDIUM,
                description=description,
                evidence=match.group(0),
            ))

    # Homoglyph detection
    homoglyphs = _HOMOGLYPH_PATTERN.findall(text)
    if len(homoglyphs) > 3:
        findings.append(Finding(
            category="prompt_injection",
            severity=Severity.HIGH,
            description="Homoglyph characters detected — possible filter evasion",
            evidence=f"count={len(homoglyphs)}, chars={''.join(set(homoglyphs))[:20]}",
        ))

    # Invisible character detection
    invisible = _INVISIBLE_CHARS_PATTERN.findall(text)
    if invisible:
        findings.append(Finding(
            category="prompt_injection",
            severity=Severity.HIGH,
            description="Invisible / zero-width characters detected — possible hidden text",
            evidence=f"count={len(invisible)}",
        ))

    # Base64 payload check
    findings.extend(_check_base64_payloads(text))

    logger.info({
        "event": "prompt_injection_scan_complete",
        "findings": len(findings),
    })
    return findings
