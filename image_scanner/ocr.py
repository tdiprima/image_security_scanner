"""Extract text from images using Tesseract OCR."""

import logging

from PIL import Image

from image_scanner.config import get_ocr_lang, get_ocr_timeout_seconds

logger = logging.getLogger(__name__)

try:
    import pytesseract
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False
    logger.warning({"event": "ocr_unavailable", "reason": "pytesseract not installed"})


class OCRError(Exception):
    """Raised when OCR cannot be performed on an image."""


def extract_text(image: Image.Image) -> str:
    """Return all text found in the image.

    Raises OCRError if pytesseract is unavailable, extraction fails, or the
    Tesseract process exceeds SCANNER_OCR_TIMEOUT_SECONDS, so callers never
    mistake a failed OCR pass for an image with no text.
    """
    if not _OCR_AVAILABLE:
        raise OCRError("pytesseract not installed")
    timeout = get_ocr_timeout_seconds()
    try:
        text = pytesseract.image_to_string(image, lang=get_ocr_lang(), timeout=timeout)
    except RuntimeError as exc:  # pytesseract raises RuntimeError on timeout
        logger.error({"event": "ocr_timeout", "timeout_seconds": timeout, "error": str(exc)})
        raise OCRError(f"timed out after {timeout:g}s") from exc
    except Exception as exc:
        logger.error({"event": "ocr_failed", "error": str(exc)})
        raise OCRError(str(exc)) from exc
    logger.debug({"event": "ocr_complete", "chars_extracted": len(text)})
    return text


def extract_text_with_confidence(image: Image.Image) -> list[dict]:
    """Return per-word OCR data including confidence scores."""
    if not _OCR_AVAILABLE:
        return []
    try:
        data = pytesseract.image_to_data(
            image,
            lang=get_ocr_lang(),
            output_type=pytesseract.Output.DICT,
            timeout=get_ocr_timeout_seconds(),
        )
        words = [
            {
                "text": data["text"][i],
                "conf": int(data["conf"][i]),
                "left": data["left"][i],
                "top": data["top"][i],
            }
            for i in range(len(data["text"]))
            if data["text"][i].strip() and int(data["conf"][i]) > 0
        ]
        return words
    except Exception as exc:
        logger.error({"event": "ocr_data_failed", "error": str(exc)})
        return []
