"""Inspect image metadata (EXIF, PNG chunks, comments) for malicious content."""

import logging
import re
import struct

from PIL import Image

from image_scanner.models import DetectorError, Finding, Severity
from image_scanner.prompt_injection import scan_for_prompt_injection

logger = logging.getLogger(__name__)

_SCRIPT_PATTERN = re.compile(
    r"<script|javascript:|data:text/html|eval\(|exec\(|__import__|os\.system",
    re.IGNORECASE,
)

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]{10,}",
    re.IGNORECASE,
)


def _scan_string_value(key: str, value: str) -> list[Finding]:
    findings: list[Finding] = []

    if _SCRIPT_PATTERN.search(value):
        findings.append(Finding(
            category="malicious_metadata",
            severity=Severity.CRITICAL,
            description=f"Script or code execution pattern in metadata field '{key}'",
            evidence=value[:120],
        ))

    urls = _URL_PATTERN.findall(value)
    if urls:
        findings.append(Finding(
            category="suspicious_metadata",
            severity=Severity.MEDIUM,
            description=f"External URL embedded in metadata field '{key}'",
            evidence=", ".join(urls[:3]),
        ))

    # Reuse prompt injection scanner on metadata text.
    injection_findings = scan_for_prompt_injection(value)
    for finding in injection_findings:
        finding.description = f"[metadata:{key}] {finding.description}"
        findings.append(finding)

    return findings


def _read_exif(image: Image.Image) -> dict[str, str]:
    """Return a flat dict of EXIF tag names to string values.

    Uses the public ``getexif()`` API (works for JPEG, TIFF, PNG, WEBP) and walks
    the Exif, GPS and Interop sub-IFDs so nothing string-bearing is skipped.

    Raises DetectorError if any IFD cannot be read — a partially read EXIF block
    must not be mistaken for a fully inspected one.
    """
    exif_data: dict[str, str] = {}
    try:
        from PIL.ExifTags import GPSTAGS, IFD, TAGS

        exif = image.getexif()
        if not exif:
            return exif_data

        def _collect(items, names: dict, prefix: str = "") -> None:
            for tag_id, value in items:
                tag_name = names.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                if isinstance(value, str):
                    exif_data[f"{prefix}{tag_name}"] = value

        _collect(exif.items(), TAGS)
        for ifd, names, prefix in (
            (IFD.Exif, TAGS, "Exif."),
            (IFD.GPSInfo, GPSTAGS, "GPS."),
            (IFD.Interop, TAGS, "Interop."),
        ):
            try:
                _collect(exif.get_ifd(ifd).items(), names, prefix)
            except Exception as exc:
                logger.warning({"event": "exif_ifd_read_failed", "ifd": ifd.name, "error": str(exc)})
                raise DetectorError(f"EXIF {ifd.name} IFD unreadable: {exc}") from exc
    except DetectorError:
        raise
    except Exception as exc:
        logger.warning({"event": "exif_read_failed", "error": str(exc)})
        raise DetectorError(f"EXIF unreadable: {exc}") from exc
    return exif_data


def _read_png_metadata(image: Image.Image) -> dict[str, str]:
    """Return PNG tEXt / iTXt / zTXt chunk contents."""
    if image.format != "PNG":
        return {}
    info = image.info
    return {k: str(v) for k, v in info.items() if isinstance(v, (str, bytes, int, float))}


def _read_jpeg_comments(image: Image.Image) -> dict[str, str]:
    """Extract JPEG APP comment segments."""
    comments: dict[str, str] = {}
    try:
        import io
        image_bytes = io.BytesIO()
        image.save(image_bytes, format="JPEG")
        data = image_bytes.getvalue()
        offset = 2  # skip SOI marker
        while offset < len(data) - 1:
            marker = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            if marker == 0xFFD9:  # EOI
                break
            if marker == 0xFFFE:  # COM
                length = struct.unpack(">H", data[offset:offset + 2])[0]
                comment = data[offset + 2:offset + length].decode("utf-8", errors="replace")
                comments[f"JPEG_COM_{offset}"] = comment
            if offset + 2 > len(data):
                break
            segment_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += segment_len
    except Exception as exc:
        logger.warning({"event": "jpeg_comment_read_failed", "error": str(exc)})
        raise DetectorError(f"JPEG comment segments unreadable: {exc}") from exc
    return comments


def analyze_metadata(image: Image.Image) -> list[Finding]:
    """Return all metadata-related findings for the image.

    Raises DetectorError if any metadata source cannot be fully read.
    """
    findings: list[Finding] = []
    all_metadata: dict[str, str] = {}

    all_metadata.update(_read_exif(image))
    all_metadata.update(_read_png_metadata(image))
    if image.format == "JPEG":
        all_metadata.update(_read_jpeg_comments(image))

    logger.debug({"event": "metadata_read", "fields": list(all_metadata.keys())})

    for key, value in all_metadata.items():
        findings.extend(_scan_string_value(key, value))

    return findings
