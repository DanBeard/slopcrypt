"""
Compression algorithms for SlopCrypt steganography.

Includes Huffman and Arithmetic coding implementations optimized
for cross-language compatibility (Python/TypeScript).
"""

import heapq
from dataclasses import dataclass
from typing import Optional

# Compression type constants
COMPRESSION_NONE = 0
COMPRESSION_HUFFMAN = 1
COMPRESSION_ARITHMETIC = 2

# Default English byte frequencies (based on typical text)
# Frequencies are relative counts, will be normalized
DEFAULT_FREQUENCIES: dict[int, int] = {
    32: 18000,  # space
    101: 12000,  # e
    116: 9000,  # t
    97: 8000,  # a
    111: 7500,  # o
    105: 7000,  # i
    110: 6700,  # n
    115: 6300,  # s
    104: 6000,  # h
    114: 5900,  # r
    100: 4200,  # d
    108: 4000,  # l
    99: 2700,  # c
    117: 2700,  # u
    109: 2400,  # m
    119: 2300,  # w
    102: 2200,  # f
    103: 2000,  # g
    121: 1900,  # y
    112: 1900,  # p
    98: 1500,  # b
    118: 1000,  # v
    107: 800,  # k
    106: 150,  # j
    120: 150,  # x
    113: 100,  # q
    122: 70,  # z
    # Uppercase
    84: 800,  # T
    73: 700,  # I
    65: 600,  # A
    83: 500,  # S
    72: 400,  # H
    87: 350,  # W
    67: 300,  # C
    66: 250,  # B
    80: 200,  # P
    77: 200,  # M
    70: 180,  # F
    68: 170,  # D
    82: 160,  # R
    76: 150,  # L
    78: 140,  # N
    69: 130,  # E
    71: 120,  # G
    79: 110,  # O
    85: 100,  # U
    86: 90,  # V
    89: 80,  # Y
    75: 70,  # K
    74: 60,  # J
    88: 50,  # X
    81: 40,  # Q
    90: 30,  # Z
    # Punctuation and digits
    46: 600,  # .
    44: 500,  # ,
    39: 200,  # '
    34: 150,  # "
    33: 100,  # !
    63: 100,  # ?
    45: 80,  # -
    58: 60,  # :
    59: 50,  # ;
    40: 40,  # (
    41: 40,  # )
    48: 50,  # 0
    49: 50,  # 1
    50: 40,  # 2
    51: 35,  # 3
    52: 30,  # 4
    53: 30,  # 5
    54: 25,  # 6
    55: 25,  # 7
    56: 20,  # 8
    57: 20,  # 9
    10: 300,  # newline
}


# ============================================================================
# Huffman Coding
# ============================================================================


@dataclass
class HuffmanNode:
    """Node in Huffman tree."""

    freq: int
    seq: int = 0  # Sequence number for deterministic tie-breaking
    byte: int | None = None  # None for internal nodes
    left: Optional["HuffmanNode"] = None
    right: Optional["HuffmanNode"] = None

    def __lt__(self, other):
        # Compare by frequency first, then by sequence number for deterministic ordering
        # This matches TypeScript's PriorityQueue behavior
        if self.freq != other.freq:
            return self.freq < other.freq
        return self.seq < other.seq


def build_huffman_tree(frequencies: dict[int, int]) -> HuffmanNode | None:
    """Build Huffman tree from byte frequencies."""
    if not frequencies:
        return None

    # Create leaf nodes - sort by byte value for deterministic cross-language compatibility
    # This ensures Python and TypeScript build identical trees regardless of dict iteration order
    sorted_items = sorted(frequencies.items(), key=lambda x: x[0])
    # Assign sequence numbers for deterministic tie-breaking when frequencies are equal
    heap = [HuffmanNode(freq=freq, seq=i, byte=byte) for i, (byte, freq) in enumerate(sorted_items)]
    heapq.heapify(heap)
    # Track sequence counter for internal nodes
    seq_counter = len(heap)

    # Build tree
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        internal = HuffmanNode(freq=left.freq + right.freq, seq=seq_counter, left=left, right=right)
        seq_counter += 1
        heapq.heappush(heap, internal)

    return heap[0] if heap else None


def _build_codes(node: HuffmanNode | None, prefix: str, codes: dict[int, str]) -> None:
    """Recursively build Huffman codes from tree."""
    if node is None:
        return

    if node.byte is not None:
        # Leaf node
        codes[node.byte] = prefix if prefix else "0"  # Single node case
    else:
        _build_codes(node.left, prefix + "0", codes)
        _build_codes(node.right, prefix + "1", codes)


def get_huffman_codes(frequencies: dict[int, int]) -> dict[int, str]:
    """Get Huffman codes for each byte."""
    tree = build_huffman_tree(frequencies)
    codes: dict[int, str] = {}
    _build_codes(tree, "", codes)
    return codes


def huffman_encode(data: bytes, frequencies: dict[int, int]) -> bytes:
    """
    Encode data using Huffman coding.

    Returns:
        Encoded bytes: [bit_count:4][huffman_bits padded to bytes]
    """
    codes = get_huffman_codes(frequencies)

    # Build bit string
    bits = []
    for byte in data:
        if byte in codes:
            bits.extend(int(b) for b in codes[byte])
        else:
            # Fallback: use 8-bit literal with escape (255 followed by byte)
            if 255 in codes:
                bits.extend(int(b) for b in codes[255])
            bits.extend((byte >> i) & 1 for i in range(7, -1, -1))

    # Store bit count (4 bytes) + padded bits
    bit_count = len(bits)

    # Pad to byte boundary
    while len(bits) % 8 != 0:
        bits.append(0)

    # Convert to bytes
    result = bytearray(bit_count.to_bytes(4, "big"))
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)

    return bytes(result)


def huffman_decode(encoded: bytes, frequencies: dict[int, int]) -> bytes:
    """
    Decode Huffman-encoded data.

    Args:
        encoded: [bit_count:4][huffman_bits]
    """
    if len(encoded) < 4:
        raise ValueError("Encoded data too short")

    bit_count = int.from_bytes(encoded[:4], "big")
    data_bytes = encoded[4:]

    # Convert bytes to bits
    bits = []
    for byte in data_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    bits = bits[:bit_count]  # Trim padding

    # Build decode tree
    tree = build_huffman_tree(frequencies)
    if tree is None:
        return b""

    # Decode
    result = bytearray()
    node = tree
    i = 0

    while i < len(bits):
        bit = bits[i]
        i += 1

        if bit == 0:
            node = node.left
        else:
            node = node.right

        if node is None:
            raise ValueError("Invalid Huffman data")

        if node.byte is not None:
            result.append(node.byte)
            node = tree

    return bytes(result)


# ============================================================================
# Arithmetic Coding (better compression than Huffman)
# ============================================================================

# Constants for 32-bit arithmetic coding
# Using 32-bit precision ensures cross-language compatibility (Python, TypeScript)
ARITH_NUM_BITS = 32
ARITH_FULL_RANGE = 1 << ARITH_NUM_BITS  # 2^32 = 4294967296
ARITH_HALF = ARITH_FULL_RANGE >> 1  # 2^31
ARITH_QUARTER = ARITH_HALF >> 1  # 2^30
ARITH_MASK = ARITH_FULL_RANGE - 1  # For keeping values in 32-bit range


def _build_arithmetic_model(
    frequencies: dict[int, int],
) -> tuple[list[int], list[int], int]:
    """
    Build cumulative frequency model for arithmetic coding.

    Returns:
        (symbols, cumulative_freqs, total_freq)
        - symbols: list of byte values in sorted order
        - cumulative_freqs: cumulative frequency boundaries (length = len(symbols) + 1)
        - total_freq: sum of all frequencies

    Sorting by byte value ensures deterministic behavior across Python/TypeScript.
    """
    # Sort by byte value for deterministic cross-language ordering
    sorted_items = sorted(frequencies.items(), key=lambda x: x[0])

    symbols = [byte for byte, _ in sorted_items]
    freqs = [freq for _, freq in sorted_items]

    # Build cumulative frequencies: [0, f0, f0+f1, f0+f1+f2, ...]
    cumulative = [0]
    for f in freqs:
        cumulative.append(cumulative[-1] + f)

    return symbols, cumulative, cumulative[-1]


class ArithmeticEncoder:
    """
    Range-based arithmetic encoder using 32-bit integer math.

    Uses the standard range coding technique where we maintain [low, high)
    and narrow it for each symbol based on cumulative frequencies.
    """

    def __init__(self, frequencies: dict[int, int]):
        self.symbols, self.cumulative, self.total = _build_arithmetic_model(frequencies)
        self.symbol_to_idx = {s: i for i, s in enumerate(self.symbols)}

        # Encoder state
        self.low = 0
        self.high = ARITH_MASK  # FULL_RANGE - 1
        self.pending_bits = 0
        self.output_bits: list[int] = []

    def _emit_bit(self, bit: int) -> None:
        """Emit a bit and any pending opposite bits."""
        self.output_bits.append(bit)
        # Emit pending bits (opposite of emitted bit)
        opposite = 1 - bit
        for _ in range(self.pending_bits):
            self.output_bits.append(opposite)
        self.pending_bits = 0

    def _renormalize(self) -> None:
        """Renormalize the range after encoding a symbol."""
        while True:
            if self.high < ARITH_HALF:
                # Both low and high in lower half [0, 0.5)
                self._emit_bit(0)
                self.low = self.low << 1
                self.high = (self.high << 1) | 1
            elif self.low >= ARITH_HALF:
                # Both low and high in upper half [0.5, 1)
                self._emit_bit(1)
                self.low = (self.low - ARITH_HALF) << 1
                self.high = ((self.high - ARITH_HALF) << 1) | 1
            elif self.low >= ARITH_QUARTER and self.high < 3 * ARITH_QUARTER:
                # Range straddles midpoint [0.25, 0.75)
                # We can't emit a bit yet, but we can scale
                self.pending_bits += 1
                self.low = (self.low - ARITH_QUARTER) << 1
                self.high = ((self.high - ARITH_QUARTER) << 1) | 1
            else:
                break

    def encode_symbol(self, byte: int) -> None:
        """Encode a single byte."""
        if byte not in self.symbol_to_idx:
            raise ValueError(f"Symbol {byte} not in frequency table")

        idx = self.symbol_to_idx[byte]
        range_size = self.high - self.low + 1

        # Narrow the range based on cumulative frequencies
        # high = low + (range * cum_high / total) - 1
        # low = low + (range * cum_low / total)
        cum_low = self.cumulative[idx]
        cum_high = self.cumulative[idx + 1]

        # Integer division - order matters to avoid overflow
        self.high = self.low + (range_size * cum_high // self.total) - 1
        self.low = self.low + (range_size * cum_low // self.total)

        self._renormalize()

    def finish(self) -> bytes:
        """Finish encoding and return the compressed bytes."""
        # Flush remaining bits to uniquely identify the final range
        self.pending_bits += 1
        if self.low < ARITH_QUARTER:
            self._emit_bit(0)
        else:
            self._emit_bit(1)

        # Pad to byte boundary
        while len(self.output_bits) % 8 != 0:
            self.output_bits.append(0)

        # Convert bits to bytes
        result = bytearray()
        for i in range(0, len(self.output_bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | self.output_bits[i + j]
            result.append(byte)

        return bytes(result)


class ArithmeticDecoder:
    """
    Range-based arithmetic decoder using 32-bit integer math.
    """

    def __init__(self, frequencies: dict[int, int], encoded_bits: list[int]):
        self.symbols, self.cumulative, self.total = _build_arithmetic_model(frequencies)
        self.bits = encoded_bits
        self.bit_index = 0

        # Decoder state
        self.low = 0
        self.high = ARITH_MASK
        self.value = 0

        # Initialize value from first 32 bits
        for _ in range(ARITH_NUM_BITS):
            self.value = (self.value << 1) | self._read_bit()

    def _read_bit(self) -> int:
        """Read next bit from input, return 0 if exhausted."""
        if self.bit_index < len(self.bits):
            bit = self.bits[self.bit_index]
            self.bit_index += 1
            return bit
        return 0

    def _renormalize(self) -> None:
        """Renormalize the range after decoding a symbol."""
        while True:
            if self.high < ARITH_HALF:
                # Both in lower half
                self.low = self.low << 1
                self.high = (self.high << 1) | 1
                self.value = (self.value << 1) | self._read_bit()
            elif self.low >= ARITH_HALF:
                # Both in upper half
                self.low = (self.low - ARITH_HALF) << 1
                self.high = ((self.high - ARITH_HALF) << 1) | 1
                self.value = ((self.value - ARITH_HALF) << 1) | self._read_bit()
            elif self.low >= ARITH_QUARTER and self.high < 3 * ARITH_QUARTER:
                # Range straddles midpoint
                self.low = (self.low - ARITH_QUARTER) << 1
                self.high = ((self.high - ARITH_QUARTER) << 1) | 1
                self.value = ((self.value - ARITH_QUARTER) << 1) | self._read_bit()
            else:
                break

    def decode_symbol(self) -> int:
        """Decode and return the next byte."""
        range_size = self.high - self.low + 1

        # Find which symbol the current value corresponds to
        # scaled_value approximates (value - low) * total / range
        scaled_value = ((self.value - self.low + 1) * self.total - 1) // range_size

        # Binary search for the symbol
        # Find largest idx where cumulative[idx] <= scaled_value
        lo, hi = 0, len(self.symbols)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.cumulative[mid] <= scaled_value:
                lo = mid
            else:
                hi = mid - 1
        idx = lo

        # Update range (same as encoder)
        cum_low = self.cumulative[idx]
        cum_high = self.cumulative[idx + 1]

        self.high = self.low + (range_size * cum_high // self.total) - 1
        self.low = self.low + (range_size * cum_low // self.total)

        self._renormalize()

        return self.symbols[idx]


def arithmetic_encode(data: bytes, frequencies: dict[int, int]) -> bytes:
    """
    Encode data using arithmetic coding.

    Returns:
        Encoded bytes: [original_length:4][encoded_data]

    Uses 32-bit integer arithmetic for cross-language compatibility.
    """
    if len(data) == 0:
        return (0).to_bytes(4, "big")

    encoder = ArithmeticEncoder(frequencies)

    for byte in data:
        encoder.encode_symbol(byte)

    encoded = encoder.finish()

    # Prepend original length (4 bytes, big-endian)
    result = bytearray(len(data).to_bytes(4, "big"))
    result.extend(encoded)

    return bytes(result)


def arithmetic_decode(encoded: bytes, frequencies: dict[int, int]) -> bytes:
    """
    Decode arithmetic-coded data.

    Args:
        encoded: [original_length:4][encoded_data]

    Returns:
        Decoded bytes
    """
    if len(encoded) < 4:
        raise ValueError("Encoded data too short")

    original_length = int.from_bytes(encoded[:4], "big")
    if original_length == 0:
        return b""

    data_bytes = encoded[4:]

    # Convert bytes to bits
    bits = []
    for byte in data_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    decoder = ArithmeticDecoder(frequencies, bits)

    result = bytearray()
    for _ in range(original_length):
        result.append(decoder.decode_symbol())

    return bytes(result)


# ============================================================================
# Public API
# ============================================================================


def compress_payload(data: bytes, frequencies: dict[int, int]) -> tuple[bytes, int]:
    """
    Compress payload, choosing best method.

    Tries arithmetic coding first (best compression), then Huffman,
    then falls back to raw if compression increases size.

    Returns:
        Tuple of (compressed_data, compression_type)
    """
    if len(data) == 0:
        return data, COMPRESSION_NONE

    candidates = [
        (data, COMPRESSION_NONE),
    ]

    # Try Huffman coding (handles unknown bytes via escape mechanism)
    huffman_encoded = huffman_encode(data, frequencies)
    candidates.append((huffman_encoded, COMPRESSION_HUFFMAN))

    # Try arithmetic coding (typically 10-20% better than Huffman)
    # Only works if all bytes in data are in the frequency table
    all_bytes_known = all(byte in frequencies for byte in data)
    if all_bytes_known:
        arith_encoded = arithmetic_encode(data, frequencies)
        candidates.append((arith_encoded, COMPRESSION_ARITHMETIC))

    # Return smallest by byte length
    return min(candidates, key=lambda x: len(x[0]))


def decompress_payload(data: bytes, compression_type: int, frequencies: dict[int, int]) -> bytes:
    """Decompress payload based on compression type."""
    if compression_type == COMPRESSION_NONE:
        return data
    elif compression_type == COMPRESSION_HUFFMAN:
        return huffman_decode(data, frequencies)
    elif compression_type == COMPRESSION_ARITHMETIC:
        return arithmetic_decode(data, frequencies)
    else:
        raise ValueError(f"Unknown compression type: {compression_type}")


def build_frequency_table(sample: bytes) -> dict[int, int]:
    """Build frequency table from sample text."""
    freq: dict[int, int] = {}
    for byte in sample:
        freq[byte] = freq.get(byte, 0) + 1

    # Ensure all printable ASCII have at least frequency 1
    for i in range(32, 127):
        if i not in freq:
            freq[i] = 1

    # Add newline and tab
    for i in [9, 10, 13]:
        if i not in freq:
            freq[i] = 1

    return freq
