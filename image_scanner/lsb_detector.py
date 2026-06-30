"""LSB steganography detection via chi-square and RS analysis."""

import logging

import numpy as np
from PIL import Image
from scipy.stats import chi2

from image_scanner.config import get_chi_square_threshold, get_rs_threshold
from image_scanner.models import Finding, Severity

logger = logging.getLogger(__name__)

_CHANNEL_NAMES = ("red", "green", "blue")
_MIN_POPULATED_PAIRS = 5
_MIN_RS_GROUPS = 100
_RS_GROUP_SIZE = 4


def _chi_square_pov(channel: np.ndarray) -> float:
    """Chi-square test on Pairs of Values for LSB replacement detection.

    LSB embedding equalises the frequencies of pixel-value pairs (2k, 2k+1).
    A high p-value means the pairs are suspiciously equal — likely embedded.
    """
    histogram, _ = np.histogram(channel.flatten(), bins=256, range=(0, 256))

    even_counts = histogram[0::2].astype(np.float64)
    odd_counts = histogram[1::2].astype(np.float64)
    pair_totals = even_counts + odd_counts

    valid = pair_totals >= 2
    if np.sum(valid) < _MIN_POPULATED_PAIRS:
        return 0.0

    expected = pair_totals[valid] / 2.0
    chi_sq = float(
        np.sum((even_counts[valid] - expected) ** 2 / expected)
        + np.sum((odd_counts[valid] - expected) ** 2 / expected)
    )
    degrees_of_freedom = int(np.sum(valid))

    return float(1.0 - chi2.cdf(chi_sq, degrees_of_freedom))


def _rs_discrimination(groups: np.ndarray) -> np.ndarray:
    """Smoothness: sum of absolute differences between adjacent pixels in each group."""
    return np.sum(np.abs(np.diff(groups.astype(np.int16), axis=1)), axis=1)


def _rs_embedding_rate(channel: np.ndarray) -> float:
    """Estimate LSB embedding via RS analysis.

    Compares Regular/Singular group counts under F1 vs F_{-1} flipping.
    In clean images R_m ~ R_{-m} and S_m ~ S_{-m}; embedding causes divergence.
    """
    flat = channel.flatten()
    n_groups = len(flat) // _RS_GROUP_SIZE
    if n_groups < _MIN_RS_GROUPS:
        return 0.0

    groups = flat[: n_groups * _RS_GROUP_SIZE].reshape(-1, _RS_GROUP_SIZE)
    smoothness_orig = _rs_discrimination(groups)

    # Skip flat groups (all pixels identical) — uninformative and cause false positives
    informative = smoothness_orig > 0
    if np.sum(informative) < _MIN_RS_GROUPS:
        return 0.0

    groups = groups[informative]
    smoothness_orig = smoothness_orig[informative]

    # F1 flip (swap within PoV pairs: 0<->1, 2<->3, ...) on odd-indexed columns
    groups_f1 = groups.copy()
    groups_f1[:, 1::2] ^= 1
    smoothness_f1 = _rs_discrimination(groups_f1)

    # F_{-1} flip (swap across PoV boundaries: 1<->2, 3<->4, ...) on odd-indexed columns
    groups_fn = groups.copy()
    odd_cols = groups_fn[:, 1::2].astype(np.int16)
    groups_fn[:, 1::2] = np.clip(
        np.where(odd_cols % 2 == 0, odd_cols - 1, odd_cols + 1), 0, 255
    ).astype(np.uint8)
    smoothness_fn = _rs_discrimination(groups_fn)

    r_m = np.mean(smoothness_f1 > smoothness_orig)
    s_m = np.mean(smoothness_f1 < smoothness_orig)
    r_neg = np.mean(smoothness_fn > smoothness_orig)
    s_neg = np.mean(smoothness_fn < smoothness_orig)

    return float((abs(r_m - r_neg) + abs(s_m - s_neg)) / 2.0)


def check_lsb_steganography(image: Image.Image) -> list[Finding]:
    """Detect LSB steganography using chi-square and RS analysis."""
    findings: list[Finding] = []
    chi_threshold = get_chi_square_threshold()
    rs_threshold = get_rs_threshold()

    try:
        rgb = image.convert("RGB")
        arr = np.array(rgb, dtype=np.uint8)

        chi_results = {}
        rs_results = {}

        for idx, name in enumerate(_CHANNEL_NAMES):
            channel = arr[:, :, idx]
            chi_results[name] = _chi_square_pov(channel)
            rs_results[name] = _rs_embedding_rate(channel)

        logger.debug({
            "event": "lsb_check",
            "chi_square_pvalues": chi_results,
            "rs_divergences": rs_results,
        })

        flagged_chi = {
            name: pval for name, pval in chi_results.items() if pval > chi_threshold
        }
        if flagged_chi:
            worst = max(flagged_chi, key=flagged_chi.get)
            findings.append(Finding(
                category="steganography",
                severity=Severity.HIGH,
                description="Chi-square analysis indicates LSB steganography",
                evidence=(
                    f"channel={worst} p_value={flagged_chi[worst]:.4f} "
                    f"threshold={chi_threshold}"
                ),
            ))

        flagged_rs = {
            name: div for name, div in rs_results.items() if div > rs_threshold
        }
        if flagged_rs:
            worst = max(flagged_rs, key=flagged_rs.get)
            findings.append(Finding(
                category="steganography",
                severity=Severity.HIGH,
                description="RS analysis indicates LSB steganography",
                evidence=(
                    f"channel={worst} rs_divergence={flagged_rs[worst]:.4f} "
                    f"threshold={rs_threshold}"
                ),
            ))
    except Exception as exc:
        logger.error({"event": "lsb_check_failed", "error": str(exc)})

    return findings
