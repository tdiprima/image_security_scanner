"""Core scan orchestration — loads an image and runs all checks."""

import logging
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from image_scanner.config import get_max_image_bytes
from image_scanner.content_heuristics import run_all_heuristics
from image_scanner.metadata_analyzer import analyze_metadata
from image_scanner.models import Finding, ScanResult, Severity
from image_scanner.ocr import extract_text
from image_scanner.prompt_injection import scan_for_prompt_injection

logger = logging.getLogger(__name__)

_ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP", "TIFF", "GIF"}


def _validate_image_path(image_path: str) -> str | None:
    """Return an error message if the path is invalid, else None."""
    if not Path(image_path).is_file():
        return f"File not found: {image_path}"
    size = Path(image_path).stat().st_size
    if size > get_max_image_bytes():
        return f"File too large: {size} bytes (limit {get_max_image_bytes()})"
    return None


def scan_image(image_path: str) -> ScanResult:
    """Run all security checks on a single image and return a ScanResult."""
    result = ScanResult(image_path=image_path)

    validation_error = _validate_image_path(image_path)
    if validation_error:
        result.error = validation_error
        logger.warning({"event": "scan_skipped", "image_path": image_path, "reason": validation_error})
        return result

    try:
        image = Image.open(image_path)
        image.verify()  # detects truncated / corrupted files
        image = Image.open(image_path)  # re-open after verify() closes the file
    except UnidentifiedImageError:
        result.error = "Unrecognized image format"
        return result
    except Exception as exc:
        result.error = f"Failed to open image: {exc}"
        return result

    if image.format not in _ALLOWED_FORMATS:
        result.add_finding(Finding(
            category="unsupported_format",
            severity=Severity.LOW,
            description=f"Unexpected image format: {image.format}",
            evidence=f"format={image.format}",
        ))

    logger.info({"event": "scan_start", "image_path": image_path, "format": image.format})

    # 1 — OCR text extraction + prompt injection scan
    extracted_text = extract_text(image)
    result.extracted_text = extracted_text
    for finding in scan_for_prompt_injection(extracted_text):
        result.add_finding(finding)

    # 2 — Metadata analysis
    for finding in analyze_metadata(image):
        result.add_finding(finding)

    # 3 — Pixel-level heuristics (entropy, LSB steganography, invisible text, dimensions)
    for finding in run_all_heuristics(image):
        result.add_finding(finding)

    return result
