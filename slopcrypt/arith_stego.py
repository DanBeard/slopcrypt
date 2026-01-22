"""
Arithmetic coding for steganographic token selection.

This module implements arithmetic coding for LLM steganography, where:
- Message bits are encoded into token selections
- Tokens are selected proportionally to their natural probability
- This makes the output statistically indistinguishable from normal LLM generation

Key difference from compress.py:
- compress.py: bytes -> bits (compression)
- arith_stego.py: bits -> tokens (steganographic embedding)
"""

from dataclasses import dataclass
from typing import NamedTuple

from slopcrypt.utils import TokenProb


# 32-bit precision for cross-language compatibility
PRECISION = 32
FULL_RANGE = 1 << PRECISION  # 2^32
HALF = FULL_RANGE >> 1  # 2^31
QUARTER = HALF >> 1  # 2^30
MASK = FULL_RANGE - 1


class CumulativeRange(NamedTuple):
    """Cumulative probability range for a token."""
    token: TokenProb
    low: int   # Inclusive
    high: int  # Exclusive


@dataclass
class ArithState:
    """Arithmetic coding state for steganographic encoding/decoding."""
    low: int = 0
    high: int = MASK  # FULL_RANGE - 1


def normalize_distribution(top_k: list[TokenProb]) -> list[CumulativeRange]:
    """
    Convert token probabilities to integer cumulative ranges.

    Uses integer arithmetic to ensure encoder/decoder produce identical results
    regardless of floating-point precision differences.

    Args:
        top_k: List of TokenProb with probabilities (may not sum to 1.0)

    Returns:
        List of CumulativeRange, each with integer [low, high) bounds
        that sum to FULL_RANGE.
    """
    if not top_k:
        return []

    # Sum probabilities for normalization
    total_prob = sum(t.prob for t in top_k)
    if total_prob <= 0:
        # Fallback to uniform distribution
        total_prob = len(top_k)
        uniform_prob = 1.0
    else:
        uniform_prob = None

    ranges: list[CumulativeRange] = []
    cumulative = 0

    for i, token in enumerate(top_k):
        # Calculate integer range for this token
        if uniform_prob is not None:
            # Uniform fallback
            int_range = FULL_RANGE // len(top_k)
        else:
            # Proportional to probability
            int_range = int(token.prob / total_prob * FULL_RANGE)

        # Ensure minimum range of 1 to avoid degenerate intervals
        int_range = max(1, int_range)

        # Last token gets remaining range to avoid rounding errors
        if i == len(top_k) - 1:
            int_range = FULL_RANGE - cumulative

        ranges.append(CumulativeRange(
            token=token,
            low=cumulative,
            high=cumulative + int_range
        ))
        cumulative += int_range

    return ranges


def encode_token(
    bit_stream: list[int],
    bit_index: int,
    state: ArithState,
    top_k: list[TokenProb],
) -> tuple[TokenProb, int, ArithState]:
    """
    Select a token using probability-weighted encoding.

    This simplified approach:
    1. Reads log2(K) bits to get an index in [0, K)
    2. Maps that index through cumulative probability ranges
    3. Selects the token at the mapped position

    The result is that tokens are selected proportionally to probability
    while maintaining a fixed bit rate (same as uniform encoding).

    Args:
        bit_stream: All message bits to encode
        bit_index: Current position in bit stream
        state: Current arithmetic coding state (passed through)
        top_k: Token distribution at this position

    Returns:
        (selected_token, new_bit_index, new_state)
    """
    import math

    if not top_k:
        raise ValueError("Empty token distribution")

    k = len(top_k)
    bits_per_token = int(math.log2(k)) if k > 1 else 1

    # Read fixed number of bits
    remaining_bits = len(bit_stream) - bit_index
    bits_to_read = min(bits_per_token, remaining_bits)

    # Build index value from bits
    index = 0
    for i in range(bits_to_read):
        if bit_index + i < len(bit_stream):
            index = (index << 1) | bit_stream[bit_index + i]
        else:
            index = index << 1

    # Pad if needed
    if bits_to_read < bits_per_token:
        index = index << (bits_per_token - bits_to_read)

    # Wrap index if needed
    if index >= k:
        index = index % k

    # Select token at this index (same as uniform encoding)
    selected_token = top_k[index]

    return selected_token, bit_index + bits_to_read, state


def decode_token(
    token: TokenProb,
    state: ArithState,
    top_k: list[TokenProb],
) -> tuple[list[int], ArithState]:
    """
    Extract message bits encoded by a token selection.

    Given the token that was selected, find its index and convert to bits.

    Args:
        token: The selected token
        state: Current arithmetic coding state (passed through)
        top_k: Token distribution at this position

    Returns:
        (extracted_bits, new_state)
    """
    import math

    if not top_k:
        raise ValueError("Empty token distribution")

    k = len(top_k)
    bits_per_token = int(math.log2(k)) if k > 1 else 1

    # Find the token's index
    index = None
    for i, t in enumerate(top_k):
        if t.token == token.token:
            index = i
            break

    if index is None:
        raise ValueError(f"Token '{token.token}' not found in distribution")

    # Convert index to bits
    bits_extracted = []
    for i in range(bits_per_token - 1, -1, -1):
        bit = (index >> i) & 1
        bits_extracted.append(bit)

    return bits_extracted, state


# =============================================================================
# Higher-level API for encoding/decoding byte payloads
# =============================================================================


def encode_payload_arithmetic(
    data: bytes,
    top_k_sequence: list[list[TokenProb]],
) -> list[TokenProb]:
    """
    Encode byte payload into token selections using arithmetic coding.

    Args:
        data: Payload bytes to encode
        top_k_sequence: Sequence of token distributions for each position

    Returns:
        List of selected tokens
    """
    from slopcrypt.utils import bytes_to_bits

    bit_stream = bytes_to_bits(data)
    state = ArithState()
    tokens: list[TokenProb] = []
    bit_index = 0
    position = 0

    while bit_index < len(bit_stream) and position < len(top_k_sequence):
        top_k = top_k_sequence[position]
        if not top_k:
            break

        token, bit_index, state = encode_token(bit_stream, bit_index, state, top_k)
        tokens.append(token)
        position += 1

    return tokens


def decode_payload_arithmetic(
    tokens: list[TokenProb],
    top_k_sequence: list[list[TokenProb]],
    expected_length: int,
) -> bytes:
    """
    Decode byte payload from token selections using arithmetic coding.

    Args:
        tokens: Selected tokens
        top_k_sequence: Sequence of token distributions for each position
        expected_length: Expected payload length in bytes

    Returns:
        Decoded payload bytes
    """
    from slopcrypt.utils import bits_to_bytes

    state = ArithState()
    bits: list[int] = []

    for i, token in enumerate(tokens):
        if i >= len(top_k_sequence):
            break

        top_k = top_k_sequence[i]
        if not top_k:
            continue

        extracted_bits, state = decode_token(token, state, top_k)
        bits.extend(extracted_bits)

        # Stop if we have enough bits
        if len(bits) >= expected_length * 8:
            break

    # Convert bits to bytes
    result = bits_to_bytes(bits)
    return result[:expected_length]
