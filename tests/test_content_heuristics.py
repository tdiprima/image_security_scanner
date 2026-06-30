"""Tests for pixel-level heuristic checks."""

import numpy as np
from PIL import Image

from image_scanner.content_heuristics import (check_aspect_ratio_anomaly,
                                              check_entropy)
from image_scanner.lsb_detector import check_lsb_steganography
from image_scanner.models import Severity


def _solid_image(color=(128, 128, 128), size=(100, 100)) -> Image.Image:
    return Image.new("RGB", size, color)


def _random_image(size=(100, 100)) -> Image.Image:
    rng = np.random.default_rng(seed=42)
    return Image.fromarray(rng.integers(0, 256, (*size[::-1], 3), dtype=np.uint8), "RGB")


def _lsb_stego_image(size=(200, 200)) -> Image.Image:
    """Create an image where LSB plane is pure random noise."""
    rng = np.random.default_rng(seed=7)
    arr = rng.integers(0, 256, (*size[::-1], 3), dtype=np.uint8)
    # Force LSB to maximum-entropy random values
    lsb_noise = rng.integers(0, 2, arr.shape, dtype=np.uint8)
    arr = (arr & 0xFE) | lsb_noise
    return Image.fromarray(arr, "RGB")


# --- Entropy ---

class TestEntropyCheck:
    def test_solid_image_no_finding(self):
        findings = check_entropy(_solid_image())
        assert findings == []

    def test_random_image_flagged(self):
        findings = check_entropy(_random_image())
        assert any(f.category == "steganography" for f in findings)

    def test_finding_severity_is_medium(self):
        findings = check_entropy(_random_image())
        stego = [f for f in findings if f.category == "steganography"]
        assert all(f.severity == Severity.MEDIUM for f in stego)


# --- LSB anomaly ---

class TestLSBAnomalyCheck:
    def test_solid_image_not_flagged(self):
        findings = check_lsb_steganography(_solid_image())
        assert findings == []

    def test_stego_image_flagged(self):
        findings = check_lsb_steganography(_lsb_stego_image())
        assert any(f.category == "steganography" for f in findings)

    def test_stego_finding_severity_is_high(self):
        findings = check_lsb_steganography(_lsb_stego_image())
        stego = [f for f in findings if f.category == "steganography"]
        assert all(f.severity == Severity.HIGH for f in stego)


# --- Aspect ratio ---

class TestAspectRatioCheck:
    def test_normal_ratio_not_flagged(self):
        findings = check_aspect_ratio_anomaly(_solid_image(size=(640, 480)))
        assert findings == []

    def test_extremely_wide_flagged(self):
        findings = check_aspect_ratio_anomaly(_solid_image(size=(5000, 10)))
        assert any(f.category == "suspicious_dimensions" for f in findings)

    def test_extremely_tall_flagged(self):
        findings = check_aspect_ratio_anomaly(_solid_image(size=(10, 5000)))
        assert any(f.category == "suspicious_dimensions" for f in findings)

    def test_severity_is_low(self):
        findings = check_aspect_ratio_anomaly(_solid_image(size=(5000, 10)))
        dim_findings = [f for f in findings if f.category == "suspicious_dimensions"]
        assert all(f.severity == Severity.LOW for f in dim_findings)
