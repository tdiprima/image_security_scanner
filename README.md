# Image Security Scanner 🖼 🔍

Images fed into AI pipelines can carry hidden threats — prompt injection text
baked into pixels, malicious instructions buried in metadata, or steganographic
payloads invisible to the naked eye. Standard content filters don't catch these.

**Solution:** A Python scanner that runs three independent checks on every image:

- **OCR + prompt injection** — extracts visible text via Tesseract and matches it
  against patterns for instruction overrides, persona hijacks, LLM control
  tokens, homoglyph substitution, invisible zero-width characters, and
  base64-encoded payloads.
- **Metadata analysis** — inspects EXIF fields, PNG text chunks, and JPEG
  comment segments for embedded scripts, external URLs, and injection text.
- **Pixel heuristics** — flags high Shannon entropy, low-contrast invisible
  text regions, and extreme aspect ratios used to smuggle text strips.

Each finding is rated **CRITICAL / HIGH / MEDIUM / LOW** and the scanner exits
non-zero when issues are found, making it CI-friendly.

## Example Output

```
============================================================
  Image Security Scan Report
  File   : suspicious.png
  Status : FLAGGED
============================================================

  [CRITICAL] prompt_injection
    Description : Instruction override attempt
    Evidence    : ignore all previous instructions

  [MEDIUM] suspicious_metadata
    Description : External URL embedded in metadata field 'Comment'
    Evidence    : https://evil.example.com/payload

  Total findings: 2
============================================================
```

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).
Also requires [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) on your system:

```bash
# macOS
brew install tesseract

# Debian / Ubuntu
sudo apt install tesseract-ocr
```

Then install the Python dependencies:

```bash
uv sync
```

## Usage

```bash
# Scan a single image (text output)
uv run image-scanner photo.png

# Scan multiple files at once
uv run image-scanner *.jpg

# Scan all images in a directory
uv run image-scanner /path/to/images/

# Scan recursively into subdirectories
uv run image-scanner /path/to/images/ --recursive

# Mix files and directories
uv run image-scanner photo.png /path/to/images/ --recursive

# JSON output — pipe into jq, save to file, etc.
uv run image-scanner /path/to/images/ --format json

# Tune behaviour via environment variables
SCANNER_LOG_LEVEL=DEBUG \
SCANNER_ENTROPY_THRESHOLD=7.2 \
SCANNER_MAX_IMAGE_BYTES=10485760 \
  uv run image-scanner suspicious.png
```

| Environment variable | Default | Description |
|---|---|---|
| `SCANNER_LOG_LEVEL` | `INFO` | Python logging level |
| `SCANNER_OCR_LANG` | `eng` | Tesseract language code |
| `SCANNER_ENTROPY_THRESHOLD` | `7.9` | Max channel entropy before flagging |
| `SCANNER_MAX_IMAGE_BYTES` | `52428800` | Max file size (50 MB) |

Exit code `0` = clean. Exit code `1` = findings or error. Exit code `2` = no image files found.

<br>
