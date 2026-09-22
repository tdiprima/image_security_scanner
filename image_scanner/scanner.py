"""Core scan orchestration — loads an image and runs all checks on every frame."""

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from PIL import Image, UnidentifiedImageError

from image_scanner.config import get_max_frames, get_max_image_bytes, get_max_image_pixels
from image_scanner.content_heuristics import run_all_heuristics
from image_scanner.metadata_analyzer import analyze_metadata
from image_scanner.models import Finding, ScanResult, Severity
from image_scanner.ocr import OCRError, extract_text
from image_scanner.prompt_injection import scan_for_prompt_injection

logger = logging.getLogger(__name__)

_ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP", "TIFF", "GIF"}

T = TypeVar("T")


def _validate_image_path(image_path: str) -> str | None:
    """Return an error message if the path is invalid, else None."""
    if not Path(image_path).is_file():
        return f"File not found: {image_path}"
    size = Path(image_path).stat().st_size
    if size > get_max_image_bytes():
        return f"File too large: {size} bytes (limit {get_max_image_bytes()})"
    return None


def _run_check(
    result: ScanResult,
    name: str,
    frame: int | None,
    check: Callable[[Image.Image], T],
    image: Image.Image,
    default: T,
) -> T:
    """Run one detector, recording any failure on the result.

    Every detector shares the same contract: return findings, or raise. Any
    exception is recorded as an error so the scan is marked incomplete and can
    never be reported clean. The batch continues with the remaining checks.
    """
    try:
        return check(image)
    except Exception as exc:
        where = f" (frame {frame})" if frame is not None else ""
        message = f"{name} failed{where}: {exc}"
        result.add_error(message)
        logger.warning({
            "event": "check_failed",
            "check": name,
            "frame": frame,
            "image_path": result.image_path,
            "error": str(exc),
        })
        return default


def _frame_count(image: Image.Image) -> int:
    """Number of frames in the image (1 for single-frame formats)."""
    return int(getattr(image, "n_frames", 1))


def _scan_frame(result: ScanResult, image: Image.Image, frame: int | None) -> str:
    """Run OCR, prompt-injection and pixel heuristics on the current frame."""
    text = _run_check(result, "OCR", frame, extract_text, image, "")
    for finding in scan_for_prompt_injection(text):
        finding.frame = frame
        result.add_finding(finding)

    for finding in _run_check(result, "Pixel heuristics", frame, run_all_heuristics, image, []):
        finding.frame = frame
        result.add_finding(finding)

    return text


def scan_image(image_path: str) -> ScanResult:
    """Run all security checks on a single image and return a ScanResult.

    Multi-frame images (GIF, TIFF, WebP) have every frame scanned, up to
    SCANNER_MAX_FRAMES. Any check that fails, any frame that cannot be decoded,
    and any exceeded budget is recorded in ``result.errors`` so the scan is
    reported as incomplete rather than clean.
    """
    result = ScanResult(image_path=image_path)

    validation_error = _validate_image_path(image_path)
    if validation_error:
        result.add_error(validation_error)
        logger.warning({"event": "scan_skipped", "image_path": image_path, "reason": validation_error})
        return result

    try:
        image = Image.open(image_path)
        image.verify()  # detects truncated / corrupted files
        image = Image.open(image_path)  # re-open after verify() closes the file
    except UnidentifiedImageError:
        result.add_error("Unrecognized image format")
        return result
    except Exception as exc:
        result.add_error(f"Failed to open image: {exc}")
        return result

    # Decoded-pixel budget: Image.open is lazy, so nothing has been decoded yet.
    width, height = image.size
    pixels = width * height
    max_pixels = get_max_image_pixels()
    if pixels > max_pixels:
        message = f"Image too large to decode: {width}x{height}={pixels} pixels (limit {max_pixels})"
        result.add_error(message)
        logger.warning({"event": "scan_skipped", "image_path": image_path, "reason": message})
        return result

    if image.format not in _ALLOWED_FORMATS:
        result.add_finding(Finding(
            category="unsupported_format",
            severity=Severity.LOW,
            description=f"Unexpected image format: {image.format}",
            evidence=f"format={image.format}",
        ))

    try:
        n_frames = _frame_count(image)
    except Exception as exc:
        result.add_error(f"Cannot determine frame count: {exc}")
        return result

    max_frames = get_max_frames()
    frames_to_scan = min(n_frames, max_frames)
    if n_frames > max_frames:
        result.add_error(
            f"Too many frames: {n_frames} (limit {max_frames}); only the first {max_frames} were scanned"
        )

    logger.info({
        "event": "scan_start",
        "image_path": image_path,
        "format": image.format,
        "size": [width, height],
        "frames": n_frames,
    })

    # Metadata is file-level: run once against the first frame.
    for finding in _run_check(result, "Metadata analysis", None, analyze_metadata, image, []):
        result.add_finding(finding)

    multiframe = n_frames > 1
    texts: list[str] = []
    for index in range(frames_to_scan):
        frame = index if multiframe else None
        if multiframe:
            try:
                image.seek(index)
            except Exception as exc:
                result.add_error(f"Cannot decode frame {index}: {exc}")
                logger.warning({"event": "frame_decode_failed", "image_path": image_path, "frame": index, "error": str(exc)})
                break
        text = _scan_frame(result, image, frame)
        if text.strip():
            texts.append(text)

    result.extracted_text = "\n".join(texts)
    return result
