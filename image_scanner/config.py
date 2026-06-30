"""Configuration loaded from environment variables with sane defaults."""

import logging
import os


def get_log_level() -> int:
    level = os.environ.get("SCANNER_LOG_LEVEL", "INFO").upper()
    return getattr(logging, level, logging.INFO)


def get_ocr_lang() -> str:
    return os.environ.get("SCANNER_OCR_LANG", "eng")


def get_entropy_threshold() -> float:
    return float(os.environ.get("SCANNER_ENTROPY_THRESHOLD", "7.9"))


def get_max_image_bytes() -> int:
    return int(os.environ.get("SCANNER_MAX_IMAGE_BYTES", str(50 * 1024 * 1024)))  # 50 MB


def get_chi_square_threshold() -> float:
    return float(os.environ.get("SCANNER_CHI_SQUARE_THRESHOLD", "0.95"))


def get_rs_threshold() -> float:
    return float(os.environ.get("SCANNER_RS_THRESHOLD", "0.05"))
