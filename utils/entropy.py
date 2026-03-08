"""
utils/entropy.py
─────────────────
Shannon entropy calculation for CSRF token strength analysis.

Extracted into a utility so it is defined exactly once and can be
imported by any module that needs to measure randomness.

Shannon Entropy Formula:
    H = − Σ (pᵢ × log₂ pᵢ)

where pᵢ is the frequency of each unique character divided by the
total length of the string. Higher values mean more randomness.

Practical reference values:
    Hex string (0-9, a-f)     → ~3.8 – 4.0 bits/char
    Base64 string             → ~4.5 – 5.0 bits/char
    Sequential / predictable  → < 2.0 bits/char
    Single repeated character → 0.0 bits/char
"""

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy in bits per character.

    Args:
        text: The string to measure (e.g. a CSRF token value).

    Returns:
        Entropy in bits/char. Returns 0.0 for empty or single-char strings.

    Example:
        >>> shannon_entropy("abc")
        1.584962500721156
        >>> shannon_entropy("aaaaaa")
        -0.0   # effectively zero
        >>> shannon_entropy("a8f3c9d2e1b7")
        3.459...
    """
    if not text or len(text) < 2:
        return 0.0

    freq   = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def classify_token_strength(length: int, entropy: float) -> str:
    """
    Classify a CSRF token's strength based on length and entropy.

    Returns one of: "Strong", "Adequate", "Weak", "Absent"
    """
    from config import (
        STRONG_TOKEN_LENGTH, STRONG_TOKEN_ENTROPY,
        MIN_TOKEN_LENGTH, MIN_TOKEN_ENTROPY,
    )

    if length == 0:
        return "Absent"
    if length >= STRONG_TOKEN_LENGTH and entropy >= STRONG_TOKEN_ENTROPY:
        return "Strong"
    if length >= MIN_TOKEN_LENGTH and entropy >= MIN_TOKEN_ENTROPY:
        return "Adequate"
    return "Weak"
