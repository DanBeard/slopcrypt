"""
Shared utilities for LLM steganography.
"""

from dataclasses import dataclass


@dataclass
class TokenProb:
    """A token with its probability."""

    token: str
    prob: float


# Bit conversion utilities


def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert list of bits to bytes."""
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)

    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def bits_to_int(bits: list[int]) -> int:
    """Convert list of bits to integer."""
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def int_to_bits(value: int, num_bits: int) -> list[int]:
    """Convert integer to list of bits."""
    bits = []
    for i in range(num_bits - 1, -1, -1):
        bits.append((value >> i) & 1)
    return bits


# Token utilities


def filter_prefix_tokens(
    dist: list[TokenProb],
    k: int,
) -> list[TokenProb]:
    """
    Filter out tokens that are prefixes of other tokens, return top-k.

    This prevents ambiguity during decoding where a shorter token
    could match when a longer one was intended.
    """
    # Sort by probability descending
    # Sort by probability descending, then by token string for deterministic ordering
    sorted_dist = sorted(dist, key=lambda x: (-x.prob, x.token))

    # Get all non-empty tokens
    all_tokens = {t.token for t in sorted_dist if t.token}

    top_k = []
    for t in sorted_dist:
        if not t.token:
            continue
        # Skip if this token is a prefix of another token
        is_prefix = any(other != t.token and other.startswith(t.token) for other in all_tokens)
        if not is_prefix:
            top_k.append(t)
        if len(top_k) >= k:
            break

    return top_k


def find_longest_match(
    text: str,
    tokens: list[TokenProb],
) -> tuple[TokenProb | None, int]:
    """
    Find the longest token matching the start of text.

    Returns:
        Tuple of (matched TokenProb or None, index in tokens list or -1)
    """
    matched_token = None
    matched_index = -1
    best_len = 0

    for idx, tp in enumerate(tokens):
        if text.startswith(tp.token) and len(tp.token) > best_len:
            matched_token = tp
            matched_index = idx
            best_len = len(tp.token)

    return matched_token, matched_index


# Knock sequence utilities


def parse_knock_sequence(knock_str: str, k: int) -> list[int]:
    """
    Parse and validate knock sequence string.

    Args:
        knock_str: Comma-separated token indices (e.g., "4,7,2,9")
        k: Maximum token index (values must be < k)

    Returns:
        List of token indices

    Raises:
        ValueError: If sequence is invalid
    """
    if not knock_str or not knock_str.strip():
        raise ValueError("Knock sequence cannot be empty")

    try:
        indices = [int(x.strip()) for x in knock_str.split(",")]
    except ValueError as e:
        raise ValueError(f"Invalid knock sequence format: {e}") from e

    if len(indices) < 4:
        import sys

        print(
            f"Warning: Short knock sequence ({len(indices)} < 4) increases false positive risk",
            file=sys.stderr,
        )

    for idx in indices:
        if idx < 0:
            raise ValueError(f"Knock index {idx} cannot be negative")
        if idx >= k:
            raise ValueError(f"Knock index {idx} exceeds K-1 ({k - 1})")

    return indices


def find_knock_sequence(indices: list[int], knock: list[int]) -> int:
    """
    Find knock sequence in list of token indices.

    Args:
        indices: List of token indices to search
        knock: Knock sequence to find

    Returns:
        Start position of knock sequence, or -1 if not found
    """
    if not knock or not indices:
        return -1

    knock_len = len(knock)
    for i in range(len(indices) - knock_len + 1):
        if indices[i : i + knock_len] == knock:
            return i
    return -1


def check_knock_in_data(data_bits: list[int], knock: list[int], bits_per_token: int) -> bool:
    """
    Check if knock sequence would appear in encoded payload.

    Args:
        data_bits: Bits to encode (including length header)
        knock: Knock sequence
        bits_per_token: log2(k)

    Returns:
        True if knock would appear in payload, False otherwise
    """
    if not knock or not data_bits:
        return False

    # Convert data bits to token indices
    indices = []
    for i in range(0, len(data_bits), bits_per_token):
        chunk = data_bits[i : i + bits_per_token]
        # Pad if needed
        while len(chunk) < bits_per_token:
            chunk.append(0)
        # Convert to index
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        indices.append(value)

    return find_knock_sequence(indices, knock) != -1
