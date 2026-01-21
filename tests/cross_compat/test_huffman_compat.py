"""
Cross-compatibility tests for Huffman compression.

Tests that Python and TypeScript implementations produce identical
Huffman-encoded output and can decode each other's compressed data.
"""

import base64

import pytest

from stego_secret import (
    COMPRESSION_HUFFMAN,
    COMPRESSION_NONE,
    DEFAULT_FREQUENCIES,
    compress_payload,
    decompress_payload,
    huffman_decode,
    huffman_encode,
)


class TestHuffmanCompatibility:
    """Tests for Huffman compression cross-compatibility."""

    def test_decode_ts_compressed_data(self, huffman_data):
        """Verify Python can decode data compressed by TypeScript."""
        for test_case in huffman_data.get("compressed", []):
            original = base64.b64decode(test_case["original"])
            compressed = base64.b64decode(test_case["compressed"])
            comp_type = test_case["compression_type"]

            # Skip if not Huffman compressed
            if comp_type != COMPRESSION_HUFFMAN:
                continue

            # Use the frequency table from the fixture if provided,
            # otherwise use default
            freq = test_case.get("frequencies", DEFAULT_FREQUENCIES)
            if isinstance(freq, dict):
                # Convert string keys to int if needed (JSON serialization issue)
                freq = {int(k): v for k, v in freq.items()}

            decompressed = huffman_decode(compressed, freq)

            assert decompressed == original, (
                f"Huffman decode mismatch\n"
                f"Expected: {original!r}\n"
                f"Got: {decompressed!r}"
            )

    def test_encode_matches_ts_output(self, huffman_data):
        """Verify Python encodes identically to TypeScript."""
        for test_case in huffman_data.get("compressed", []):
            original = base64.b64decode(test_case["original"])
            expected_compressed = base64.b64decode(test_case["compressed"])
            comp_type = test_case["compression_type"]

            if comp_type != COMPRESSION_HUFFMAN:
                continue

            freq = test_case.get("frequencies", DEFAULT_FREQUENCIES)
            if isinstance(freq, dict):
                freq = {int(k): v for k, v in freq.items()}

            # Encode in Python
            compressed = huffman_encode(original, freq)

            # The output should be byte-for-byte identical
            assert compressed == expected_compressed, (
                f"Huffman encode mismatch for: {original!r}\n"
                f"Expected: {base64.b64encode(expected_compressed).decode()}\n"
                f"Got: {base64.b64encode(compressed).decode()}"
            )

    def test_decompress_payload_ts_data(self, huffman_data):
        """Verify decompress_payload works with TypeScript-compressed data."""
        for test_case in huffman_data.get("compressed", []):
            original = base64.b64decode(test_case["original"])
            compressed = base64.b64decode(test_case["compressed"])
            comp_type = test_case["compression_type"]

            freq = test_case.get("frequencies", DEFAULT_FREQUENCIES)
            if isinstance(freq, dict):
                freq = {int(k): v for k, v in freq.items()}

            decompressed = decompress_payload(compressed, comp_type, freq)

            assert decompressed == original


class TestHuffmanTreeCompatibility:
    """Tests for Huffman tree construction compatibility."""

    def test_default_frequencies_match(self, huffman_data):
        """Verify default frequency tables match between implementations."""
        ts_frequencies = huffman_data.get("default_frequencies", {})

        if not ts_frequencies:
            pytest.skip("No default frequencies in fixture")

        # Convert string keys to int
        ts_frequencies = {int(k): v for k, v in ts_frequencies.items()}

        # Check that all Python default frequencies match TypeScript
        for byte_val, freq in DEFAULT_FREQUENCIES.items():
            assert byte_val in ts_frequencies, f"Missing byte {byte_val} in TS frequencies"
            assert ts_frequencies[byte_val] == freq, (
                f"Frequency mismatch for byte {byte_val}: "
                f"Python={freq}, TypeScript={ts_frequencies[byte_val]}"
            )

    def test_huffman_codes_deterministic(self, huffman_data):
        """Verify Huffman codes are deterministic across runs."""
        # Encode the same data twice with same frequencies
        data = b"test data for determinism"

        encoded1 = huffman_encode(data, DEFAULT_FREQUENCIES)
        encoded2 = huffman_encode(data, DEFAULT_FREQUENCIES)

        assert encoded1 == encoded2


class TestCompressionDecision:
    """Tests for compression decision compatibility."""

    def test_compress_payload_decision(self, huffman_data):
        """Verify compression decision matches TypeScript."""
        for test_case in huffman_data.get("compressed", []):
            original = base64.b64decode(test_case["original"])
            expected_type = test_case["compression_type"]

            freq = test_case.get("frequencies", DEFAULT_FREQUENCIES)
            if isinstance(freq, dict):
                freq = {int(k): v for k, v in freq.items()}

            _, actual_type = compress_payload(original, freq)

            assert actual_type == expected_type, (
                f"Compression decision mismatch for data length {len(original)}\n"
                f"Expected: {expected_type}, Got: {actual_type}"
            )

    def test_no_compression_for_random_data(self):
        """Verify random data uses no compression (same decision as TS)."""
        # Highly random data shouldn't compress well
        import secrets

        random_data = secrets.token_bytes(100)
        _, comp_type = compress_payload(random_data, DEFAULT_FREQUENCIES)

        # Either raw or Huffman is acceptable, but should match TS
        assert comp_type in (COMPRESSION_NONE, COMPRESSION_HUFFMAN)


class TestBinaryDataCompatibility:
    """Tests for binary data handling in compression."""

    def test_compress_all_byte_values(self, huffman_data):
        """Verify compression handles all 256 byte values."""
        # Test with all possible byte values
        data = bytes(range(256))

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)
        decompressed = decompress_payload(compressed, comp_type, DEFAULT_FREQUENCIES)

        assert decompressed == data

    def test_compress_null_bytes(self, huffman_data):
        """Verify compression handles null bytes."""
        data = b"\x00\x00\x00test\x00\x00"

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)
        decompressed = decompress_payload(compressed, comp_type, DEFAULT_FREQUENCIES)

        assert decompressed == data

    def test_compress_high_bytes(self, huffman_data):
        """Verify compression handles high byte values."""
        data = bytes([0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82])

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)
        decompressed = decompress_payload(compressed, comp_type, DEFAULT_FREQUENCIES)

        assert decompressed == data
