"""Extract text from images using Tesseract OCR."""

import logging

from PIL import Image

from image_scanner.config import get_ocr_lang

logger = logging.getLogger(__name__)

try:
    import pytesseract
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False
    logger.warning({"event": "ocr_unavailable", "reason": "pytesseract not installed"})


def extract_text(image: Image.Image) -> str:
    """Return all text found in the image, or empty string if OCR unavailable."""
    if not _OCR_AVAILABLE:
        return ""
    try:
        text = pytesseract.image_to_string(image, lang=get_ocr_lang())
        logger.debug({"event": "ocr_complete", "chars_extracted": len(text)})
        return text
    except Exception as exc:
        logger.error({"event": "ocr_failed", "error": str(exc)})
        return ""


def extract_text_with_confidence(image: Image.Image) -> list[dict]:
    """Return per-word OCR data including confidence scores."""
    if not _OCR_AVAILABLE:
        return []
    try:
        data = pytesseract.image_to_data(
            image, lang=get_ocr_lang(), output_type=pytesseract.Output.DICT
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
