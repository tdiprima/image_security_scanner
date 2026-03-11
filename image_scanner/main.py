"""Entry point — parse CLI arguments and run the scanner."""

import argparse
import logging
import sys

from image_scanner.config import get_log_level
from image_scanner.report import log_result, print_report
from image_scanner.scanner import scan_image


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
        metavar="IMAGE",
        help="Path(s) to image file(s) to scan.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    return parser


def main() -> None:
    _configure_logging()
    args = _build_parser().parse_args()

    exit_code = 0
    for image_path in args.images:
        result = scan_image(image_path)
        print_report(result, output_format=args.format)
        log_result(result)
        if not result.clean or result.error:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
