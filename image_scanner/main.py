"""Entry point — parse CLI arguments and run the scanner."""

import argparse
import logging
import sys
from pathlib import Path

from image_scanner.config import get_log_level
from image_scanner.report import log_result, print_report
from image_scanner.scanner import scan_image

logger = logging.getLogger(__name__)

_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".gif"}


def _configure_logging() -> None:
    logging.basicConfig(
        level=get_log_level(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan images for prompt injection and malicious content.",
    )
    parser.add_argument(
        "images",
        nargs="+",
        metavar="IMAGE_OR_DIR",
        help="Path(s) to image file(s) or directory(ies) to scan.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recurse into subdirectories when scanning a directory.",
    )
    return parser


def _collect_image_paths(inputs: list[str], recursive: bool) -> list[str]:
    """Expand directories to image file paths; pass files through as-is."""
    collected = []
    for input_path in inputs:
        path = Path(input_path)
        if path.is_dir():
            glob_fn = path.rglob if recursive else path.glob
            found = sorted(
                p for p in glob_fn("*")
                if p.is_file() and p.suffix.lower() in _IMAGE_EXTENSIONS
            )
            if not found:
                logger.warning({"event": "no_images_found", "directory": input_path})
            collected.extend(str(p) for p in found)
        else:
            collected.append(input_path)
    return collected


def main() -> None:
    _configure_logging()
    args = _build_parser().parse_args()

    image_paths = _collect_image_paths(args.images, args.recursive)

    if not image_paths:
        logger.error({"event": "no_images", "message": "No image files found to scan."})
        sys.exit(2)

    exit_code = 0
    for image_path in image_paths:
        result = scan_image(image_path)
        print_report(result, output_format=args.format)
        log_result(result)
        if not result.clean or result.error:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
