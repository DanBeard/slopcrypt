#!/usr/bin/env python3
"""
Tests for SlopCrypt Base-K encoding (slopcrypt.encode).

Run with: python -m pytest tests/test_encode.py -v
Or simply: python tests/test_encode.py
"""

import unittest

from slopcrypt.encode import decode, decode_with_knock, encode, encode_with_knock
from slopcrypt.lm_client import MockLMClient
from slopcrypt.utils import (
    TokenProb,
    bits_to_bytes,
    bits_to_int,
    bytes_to_bits,
    check_knock_in_data,
    filter_prefix_tokens,
    find_knock_sequence,
    find_longest_match,
    int_to_bits,
    parse_knock_sequence,
)


class TestBitConversions(unittest.TestCase):
    """Tests for bit conversion utilities."""

    def test_bytes_to_bits(self):
        """Test converting bytes to bits."""
        # Single byte
        self.assertEqual(bytes_to_bits(b"\x00"), [0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(bytes_to_bits(b"\xff"), [1, 1, 1, 1, 1, 1, 1, 1])
        self.assertEqual(bytes_to_bits(b"\x80"), [1, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(bytes_to_bits(b"\x01"), [0, 0, 0, 0, 0, 0, 0, 1])

        # Multiple bytes
        self.assertEqual(
            bytes_to_bits(b"\xab\xcd"), [1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1]
        )

    def test_bits_to_bytes(self):
        """Test converting bits to bytes."""
        self.assertEqual(bits_to_bytes([0, 0, 0, 0, 0, 0, 0, 0]), b"\x00")
        self.assertEqual(bits_to_bytes([1, 1, 1, 1, 1, 1, 1, 1]), b"\xff")
        self.assertEqual(bits_to_bytes([1, 0, 1, 0, 1, 0, 1, 1]), b"\xab")

    def test_bits_to_bytes_padding(self):
        """Test that bits_to_bytes pads to byte boundary."""
        # 4 bits should be padded to 8
        self.assertEqual(bits_to_bytes([1, 0, 1, 0]), b"\xa0")

    def test_bits_to_int(self):
        """Test converting bits to integer."""
        self.assertEqual(bits_to_int([0]), 0)
        self.assertEqual(bits_to_int([1]), 1)
        self.assertEqual(bits_to_int([1, 0]), 2)
        self.assertEqual(bits_to_int([1, 1]), 3)
        self.assertEqual(bits_to_int([1, 0, 1, 0]), 10)

    def test_int_to_bits(self):
        """Test converting integer to bits."""
        self.assertEqual(int_to_bits(0, 4), [0, 0, 0, 0])
        self.assertEqual(int_to_bits(1, 4), [0, 0, 0, 1])
        self.assertEqual(int_to_bits(10, 4), [1, 0, 1, 0])
        self.assertEqual(int_to_bits(15, 4), [1, 1, 1, 1])

    def test_roundtrip(self):
        """Test bytes -> bits -> bytes roundtrip."""
        original = b"\xde\xad\xbe\xef"
        bits = bytes_to_bits(original)
        recovered = bits_to_bytes(bits)
        self.assertEqual(recovered, original)


class TestTokenUtilities(unittest.TestCase):
    """Tests for token filtering and matching utilities."""

    def test_filter_prefix_tokens(self):
        """Test filtering out prefix tokens."""
        dist = [
            TokenProb(" ", 0.3),  # prefix of " the"
            TokenProb(" the", 0.2),
            TokenProb(" a", 0.15),  # prefix of " an"
            TokenProb(" an", 0.1),
            TokenProb("x", 0.05),
        ]
        result = filter_prefix_tokens(dist, k=10)

        # " " should be filtered because " the" starts with it
        # " a" should be filtered because " an" starts with it
        tokens = [t.token for t in result]
        self.assertNotIn(" ", tokens)
        self.assertNotIn(" a", tokens)
        self.assertIn(" the", tokens)
        self.assertIn(" an", tokens)
        self.assertIn("x", tokens)

    def test_filter_prefix_tokens_respects_k(self):
        """Test that filter_prefix_tokens respects the k limit."""
        dist = [TokenProb(f"t{i}", 1.0 / (i + 1)) for i in range(100)]
        result = filter_prefix_tokens(dist, k=10)
        self.assertEqual(len(result), 10)

    def test_find_longest_match(self):
        """Test finding the longest matching token."""
        tokens = [
            TokenProb(" the", 0.3),
            TokenProb(" ", 0.2),
            TokenProb(" a", 0.1),
        ]

        # Should match " the" not " "
        matched, idx = find_longest_match(" the quick", tokens)
        self.assertEqual(matched.token, " the")
        self.assertEqual(idx, 0)

    def test_find_longest_match_no_match(self):
        """Test find_longest_match when nothing matches."""
        tokens = [
            TokenProb(" the", 0.3),
            TokenProb(" a", 0.2),
        ]

        matched, idx = find_longest_match("xyz", tokens)
        self.assertIsNone(matched)
        self.assertEqual(idx, -1)


class TestMockClient(unittest.TestCase):
    """Tests for the mock LM client."""

    def test_deterministic_distribution(self):
        """Test that same context produces same distribution."""
        client = MockLMClient(vocab_size=16, seed=42)

        dist1 = client.get_token_distribution("Hello world")
        dist2 = client.get_token_distribution("Hello world")

        self.assertEqual(len(dist1), len(dist2))
        for t1, t2 in zip(dist1, dist2, strict=True):
            self.assertEqual(t1.token, t2.token)
            self.assertAlmostEqual(t1.prob, t2.prob)

    def test_different_context_different_distribution(self):
        """Test that different contexts produce different distributions."""
        client = MockLMClient(vocab_size=16, seed=42)

        dist1 = client.get_token_distribution("Hello")
        dist2 = client.get_token_distribution("Goodbye")

        # Distributions should differ (at least in ordering)
        tokens1 = [t.token for t in dist1]
        tokens2 = [t.token for t in dist2]
        probs1 = [t.prob for t in dist1]
        probs2 = [t.prob for t in dist2]

        # At least the ordering or probabilities should differ
        self.assertTrue(tokens1 != tokens2 or probs1 != probs2)


class TestBaseKSteganography(unittest.TestCase):
    """Tests for the Base-K steganography implementation."""

    def setUp(self):
        self.mock_client = MockLMClient(vocab_size=32, seed=42)
        self.prompt = "Once upon a time"

    def test_encode_decode_small(self):
        """Test full encode/decode cycle with small payload."""
        original = b"Hi!"

        cover = encode(original, self.mock_client, self.prompt, k=16)

        self.assertIsInstance(cover, str)
        self.assertGreater(len(cover), 0)

        recovered = decode(cover, self.mock_client, self.prompt, k=16)

        self.assertEqual(
            recovered,
            original,
            f"Round-trip failed. Original: {original!r}, Recovered: {recovered!r}",
        )

    def test_encode_decode_empty(self):
        """Test encoding empty payload."""
        original = b""

        cover = encode(original, self.mock_client, self.prompt, k=16)

        recovered = decode(cover, self.mock_client, self.prompt, k=16)

        self.assertEqual(recovered, original)

    def test_binary_data(self):
        """Test with actual binary (non-printable) data."""
        original = bytes(range(256))[:16]  # First 16 bytes 0x00-0x0F

        cover = encode(original, self.mock_client, self.prompt, k=16)

        recovered = decode(cover, self.mock_client, self.prompt, k=16)

        self.assertEqual(recovered, original)

    def test_all_zeros(self):
        """Test encoding data that is all zeros."""
        original = b"\x00\x00\x00\x00"

        cover = encode(original, self.mock_client, self.prompt, k=16)

        recovered = decode(cover, self.mock_client, self.prompt, k=16)

        self.assertEqual(recovered, original)

    def test_all_ones(self):
        """Test encoding data that is all 0xFF."""
        original = b"\xff\xff\xff\xff"

        cover = encode(original, self.mock_client, self.prompt, k=16)

        recovered = decode(cover, self.mock_client, self.prompt, k=16)

        self.assertEqual(recovered, original)

    def test_different_k_values(self):
        """Test with different K values."""
        original = b"Test"

        for k in [4, 8, 16, 32]:
            cover = encode(original, self.mock_client, self.prompt, k=k)
            recovered = decode(cover, self.mock_client, self.prompt, k=k)
            self.assertEqual(recovered, original, f"Failed with k={k}")


class TestKnockSequence(unittest.TestCase):
    """Tests for knock sequence utilities and encoding."""

    def test_parse_knock_sequence_valid(self):
        """Test parsing valid knock sequences."""
        result = parse_knock_sequence("4,7,2,9", k=16)
        self.assertEqual(result, [4, 7, 2, 9])

        result = parse_knock_sequence("0,1,2,3,4,5", k=16)
        self.assertEqual(result, [0, 1, 2, 3, 4, 5])

    def test_parse_knock_sequence_with_spaces(self):
        """Test parsing knock sequences with whitespace."""
        result = parse_knock_sequence("4, 7, 2, 9", k=16)
        self.assertEqual(result, [4, 7, 2, 9])

    def test_parse_knock_sequence_too_large(self):
        """Test that values >= k raise error."""
        with self.assertRaises(ValueError) as ctx:
            parse_knock_sequence("4,7,16,9", k=16)
        self.assertIn("16", str(ctx.exception))
        self.assertIn("exceeds", str(ctx.exception))

    def test_parse_knock_sequence_negative(self):
        """Test that negative values raise error."""
        with self.assertRaises(ValueError) as ctx:
            parse_knock_sequence("4,-1,2,9", k=16)
        self.assertIn("negative", str(ctx.exception))

    def test_parse_knock_sequence_empty(self):
        """Test that empty sequence raises error."""
        with self.assertRaises(ValueError):
            parse_knock_sequence("", k=16)

    def test_parse_knock_sequence_invalid_format(self):
        """Test that non-numeric values raise error."""
        with self.assertRaises(ValueError):
            parse_knock_sequence("4,a,2,9", k=16)

    def test_find_knock_sequence_found(self):
        """Test finding knock sequence in indices."""
        indices = [0, 0, 0, 4, 7, 2, 9, 1, 1, 1]
        knock = [4, 7, 2, 9]
        self.assertEqual(find_knock_sequence(indices, knock), 3)

    def test_find_knock_sequence_at_start(self):
        """Test finding knock sequence at start."""
        indices = [4, 7, 2, 9, 0, 0, 0]
        knock = [4, 7, 2, 9]
        self.assertEqual(find_knock_sequence(indices, knock), 0)

    def test_find_knock_sequence_at_end(self):
        """Test finding knock sequence at end."""
        indices = [0, 0, 0, 4, 7, 2, 9]
        knock = [4, 7, 2, 9]
        self.assertEqual(find_knock_sequence(indices, knock), 3)

    def test_find_knock_sequence_not_found(self):
        """Test when knock sequence is not present."""
        indices = [0, 1, 2, 3, 4, 5, 6]
        knock = [4, 7, 2, 9]
        self.assertEqual(find_knock_sequence(indices, knock), -1)

    def test_find_knock_sequence_partial(self):
        """Test partial knock sequence is not found."""
        indices = [4, 7, 2, 0, 0, 0]  # Missing the 9
        knock = [4, 7, 2, 9]
        self.assertEqual(find_knock_sequence(indices, knock), -1)

    def test_check_knock_in_data_not_present(self):
        """Test that random data doesn't contain knock."""
        # Small payload unlikely to contain specific sequence
        data_bits = [0, 0, 0, 0, 0, 0, 0, 0] * 4  # 4 bytes of zeros
        knock = [4, 7, 2, 9]
        self.assertFalse(check_knock_in_data(data_bits, knock, bits_per_token=4))

    def test_check_knock_in_data_present(self):
        """Test detection of knock in payload."""
        # Manually construct bits that would encode [4, 7, 2, 9] with 4 bits/token
        # 4=0100, 7=0111, 2=0010, 9=1001
        data_bits = [0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1]
        knock = [4, 7, 2, 9]
        self.assertTrue(check_knock_in_data(data_bits, knock, bits_per_token=4))


class TestKnockEncodeDecode(unittest.TestCase):
    """Tests for encode/decode with knock sequence."""

    def setUp(self):
        self.mock_client = MockLMClient(vocab_size=32, seed=42)
        self.prompt = "Once upon a time"
        self.knock = [4, 7, 2, 9]

    def test_encode_decode_with_knock_small(self):
        """Test full encode/decode cycle with knock sequence."""
        original = b"Hi!"

        cover = encode_with_knock(
            original,
            self.mock_client,
            self.prompt,
            k=16,
            knock=self.knock,
            preamble_tokens=5,
            suffix_tokens=5,
        )

        self.assertIsInstance(cover, str)
        self.assertGreater(len(cover), 0)

        recovered = decode_with_knock(cover, self.mock_client, k=16, knock=self.knock)

        self.assertEqual(
            recovered,
            original,
            f"Round-trip failed. Original: {original!r}, Recovered: {recovered!r}",
        )

    def test_encode_decode_with_knock_longer(self):
        """Test knock encode/decode with longer payload."""
        original = b"Secret message for testing!"

        cover = encode_with_knock(
            original,
            self.mock_client,
            self.prompt,
            k=16,
            knock=self.knock,
            preamble_tokens=10,
            suffix_tokens=10,
        )

        recovered = decode_with_knock(cover, self.mock_client, k=16, knock=self.knock)

        self.assertEqual(recovered, original)

    def test_encode_decode_with_knock_empty(self):
        """Test knock mode with empty payload."""
        original = b""

        cover = encode_with_knock(
            original,
            self.mock_client,
            self.prompt,
            k=16,
            knock=self.knock,
            preamble_tokens=5,
            suffix_tokens=5,
        )

        recovered = decode_with_knock(cover, self.mock_client, k=16, knock=self.knock)

        self.assertEqual(recovered, original)

    def test_decode_without_knock_fails(self):
        """Test that decoding fails with wrong knock sequence."""
        original = b"Test"

        cover = encode_with_knock(
            original,
            self.mock_client,
            self.prompt,
            k=16,
            knock=self.knock,
            preamble_tokens=5,
            suffix_tokens=5,
        )

        wrong_knock = [1, 2, 3, 4]
        with self.assertRaises(ValueError) as ctx:
            decode_with_knock(cover, self.mock_client, k=16, knock=wrong_knock)
        self.assertIn("not found", str(ctx.exception))

    def test_preamble_and_suffix_present(self):
        """Test that cover text is longer than payload-only encoding."""
        original = b"Hi!"

        # Encode without knock
        cover_no_knock = encode(original, self.mock_client, self.prompt, k=16)

        # Encode with knock (adds preamble + knock + suffix)
        cover_with_knock = encode_with_knock(
            original,
            self.mock_client,
            self.prompt,
            k=16,
            knock=self.knock,
            preamble_tokens=10,
            suffix_tokens=10,
        )

        # Cover with knock should be longer
        self.assertGreater(len(cover_with_knock), len(cover_no_knock))


def run_quick_demo():
    """Run a quick demonstration of the steganography system."""
    print("=" * 60)
    print("LLM Steganography Demo (Base-K, mock client)")
    print("=" * 60)

    client = MockLMClient(vocab_size=32, seed=42)
    prompt = "Write a story:"
    original = b"Secret!"

    print(f"\nOriginal data: {original!r} ({len(original)} bytes)")
    print(f"Prompt: {prompt!r}")

    print("\nEncoding...")
    cover = encode(original, client, prompt, k=16, verbose=False)
    print(f"Cover text ({len(cover)} chars):")
    print(f"  {cover[:100]}{'...' if len(cover) > 100 else ''}")

    print("\nDecoding...")
    recovered = decode(cover, client, prompt, k=16, verbose=False)
    print(f"Recovered data: {recovered!r}")

    if recovered == original:
        print("\n[SUCCESS] Round-trip successful!")
    else:
        print("\n[FAILURE] Data mismatch!")
        print(f"  Expected: {original!r}")
        print(f"  Got:      {recovered!r}")

    return recovered == original


if __name__ == "__main__":
    # Run demo first
    print("\n" + "=" * 60)
    print("Running quick demo...")
    print("=" * 60)
    demo_success = run_quick_demo()

    # Then run unit tests
    print("\n" + "=" * 60)
    print("Running unit tests...")
    print("=" * 60 + "\n")

    # Run tests with verbosity
    unittest.main(verbosity=2, exit=False)
