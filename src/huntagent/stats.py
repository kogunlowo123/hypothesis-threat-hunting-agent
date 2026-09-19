"""Small statistical helpers used by the hunts. Standard library only."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Sequence
from itertools import pairwise


def shannon_entropy(text: str) -> float:
    """Bits per character. Random-looking strings score high, words score low."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def coefficient_of_variation(values: Sequence[float]) -> float:
    """Population standard deviation divided by the mean. 0 means perfectly regular.

    Returns ``inf`` when the mean is not positive or there are fewer than two values.
    """
    if len(values) < 2:
        return math.inf
    mean = statistics.fmean(values)
    if mean <= 0:
        return math.inf
    return statistics.pstdev(values) / mean


def robust_zscore(value: float, sample: Sequence[float]) -> float:
    """How unusual ``value`` is against ``sample``, using the median and MAD so outliers in the
    sample do not hide themselves. Falls back to the standard deviation when the MAD is zero.

    Returns 0.0 when the sample has fewer than three points or no spread.
    """
    if len(sample) < 3:
        return 0.0
    median = statistics.median(sample)
    mad = statistics.median(abs(x - median) for x in sample)
    if mad > 0:
        return 0.6745 * (value - median) / mad
    spread = statistics.pstdev(sample)
    return (value - median) / spread if spread > 0 else 0.0


def intervals(times: Sequence[float]) -> list[float]:
    """Gaps between consecutive sorted timestamps, in the same unit."""
    ordered = sorted(times)
    return [b - a for a, b in pairwise(ordered)]


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Levenshtein distance, stopping early once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]
