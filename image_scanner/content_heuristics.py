"""Heuristic checks on image pixel data for steganography and hidden content."""

import logging
import math

import numpy as np
from PIL import Image

from image_scanner.config import get_entropy_threshold
from image_scanner.models import Finding, Severity

logger = logging.getLogger(__name__)


def _channel_entropy(channel_array: np.ndarray) -> float:
    """Calculate Shannon entropy of a single image channel (0–8 bits)."""
    histogram, _ = np.histogram(channel_array.flatten(), bins=256, range=(0, 256))
    total = histogram.sum()
    if total == 0:
        return 0.0
    probabilities = histogram[histogram > 0] / total
    return -float(np.sum(probabilities * np.log2(probabilities)))


def check_entropy(image: Image.Image) -> list[Finding]:
    """Flag images with suspiciously high entropy (potential steganography)."""
    findings: list[Finding] = []
    threshold = get_entropy_threshold()
    try:
        rgb = image.convert("RGB")
        arr = np.array(rgb, dtype=np.uint8)
        entropies = {
            "red": _channel_entropy(arr[:, :, 0]),
            "green": _channel_entropy(arr[:, :, 1]),
            "blue": _channel_entropy(arr[:, :, 2]),
        }
        max_entropy = max(entropies.values())
        logger.debug({"event": "entropy_check", "entropies": entropies})
        if max_entropy > threshold:
            findings.append(Finding(
                category="steganography",
                severity=Severity.MEDIUM,
                description="Abnormally high pixel entropy — possible steganographic payload",
                evidence=f"max_channel_entropy={max_entropy:.3f} threshold={threshold}",
            ))
    except Exception as exc:
        logger.error({"event": "entropy_check_failed", "error": str(exc)})
    return findings


def check_lsb_anomaly(image: Image.Image) -> list[Finding]:
    """Detect LSB steganography by comparing LSB randomness to expected baseline."""
    findings: list[Finding] = []
    try:
        rgb = image.convert("RGB")
        arr = np.array(rgb, dtype=np.uint8)
        lsb_plane = arr & 1  # extract least significant bits
        lsb_entropy = _channel_entropy((lsb_plane[:, :, 0] * 255).astype(np.uint8))
        # Natural images have LSB entropy well below 1.0; uniform random data approaches 1.0.
        if lsb_entropy > 0.95:
            findings.append(Finding(
                category="steganography",
                severity=Severity.HIGH,
                description="LSB plane entropy near maximum — strong indicator of LSB steganography",
                evidence=f"lsb_entropy={lsb_entropy:.4f}",
            ))
        logger.debug({"event": "lsb_check", "lsb_entropy": lsb_entropy})
    except Exception as exc:
        logger.error({"event": "lsb_check_failed", "error": str(exc)})
    return findings


def check_invisible_text(image: Image.Image) -> list[Finding]:
    """Detect near-invisible text by scanning for low-contrast regions with OCR signals."""
    findings: list[Finding] = []
    try:
        rgb = image.convert("RGB")
        arr = np.array(rgb, dtype=np.uint8)
        # Compute local contrast via standard deviation in small windows.
        from scipy.ndimage import uniform_filter
        gray = np.mean(arr, axis=2)
        mean_local = uniform_filter(gray, size=15)
        mean_sq_local = uniform_filter(gray ** 2, size=15)
        local_std = np.sqrt(np.maximum(mean_sq_local - mean_local ** 2, 0))
        low_contrast_ratio = float(np.mean(local_std < 3.0))
        logger.debug({"event": "contrast_check", "low_contrast_ratio": low_contrast_ratio})
        if low_contrast_ratio > 0.85:
            findings.append(Finding(
                category="hidden_content",
                severity=Severity.MEDIUM,
                description="Image is predominantly low-contrast — may contain invisible text",
                evidence=f"low_contrast_pixel_ratio={low_contrast_ratio:.2f}",
            ))
    except Exception as exc:
        logger.error({"event": "invisible_text_check_failed", "error": str(exc)})
    return findings


def check_aspect_ratio_anomaly(image: Image.Image) -> list[Finding]:
    """Flag extremely thin/wide images that may be used to smuggle text strips."""
    findings: list[Finding] = []
    width, height = image.size
    if height == 0:
        return findings
    ratio = width / height
    if ratio > 50 or ratio < 0.02:
        findings.append(Finding(
            category="suspicious_dimensions",
            severity=Severity.LOW,
            description="Extreme aspect ratio — image may be a hidden text strip",
            evidence=f"width={width} height={height} ratio={ratio:.1f}",
        ))
    return findings


def run_all_heuristics(image: Image.Image) -> list[Finding]:
    """Run all pixel-level heuristic checks and return combined findings."""
    findings: list[Finding] = []
    findings.extend(check_entropy(image))
    findings.extend(check_lsb_anomaly(image))
    findings.extend(check_invisible_text(image))
    findings.extend(check_aspect_ratio_anomaly(image))
    return findings
