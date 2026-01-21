"""
Cross-compatibility tests for full steganography encode/decode.

Tests that cover text encoded in Python can be decoded in TypeScript
(and vice versa) using FixedDistributionClient for determinism.
"""

import base64

import pytest

from lm_client import FixedDistributionClient
from stego_secret import (
    decode_message,
    decrypt_secret_blob,
    encode_message,
    generate_secret,
)


class TestStegoEncodeDecodeCompatibility:
    """Tests for full encode/decode cross-compatibility."""

    def test_decode_ts_encoded_cover_text(self, stego_roundtrip):
        """Verify Python can decode cover text encoded by TypeScript."""
        client = FixedDistributionClient(vocab_size=32)

        for test_case in stego_roundtrip.get("encoded", []):
            secret_blob = test_case["secret_blob"]
            password = test_case["password"]
            prompt = test_case["prompt"]
            cover_text = test_case["cover_text"]
            expected_message = base64.b64decode(test_case["expected_message"])

            # Decrypt the secret
            secret = decrypt_secret_blob(secret_blob, password)

            # Decode the cover text
            decoded = decode_message(cover_text, secret, client, prompt=prompt)

            assert decoded == expected_message, (
                f"Decode mismatch\n"
                f"Expected: {expected_message!r}\n"
                f"Got: {decoded!r}"
            )

    def test_encode_then_decode_with_ts_secret(self, stego_roundtrip):
        """Verify encoding with TS secret and decoding produces original message.

        Note: We can't test for identical cover text because AES-GCM uses random
        nonces, so each encryption produces different ciphertext. Instead we verify
        the roundtrip works correctly.
        """
        client = FixedDistributionClient(vocab_size=32)

        for test_case in stego_roundtrip.get("encoded", []):
            secret_blob = test_case["secret_blob"]
            password = test_case["password"]
            prompt = test_case["prompt"]
            original_message = base64.b64decode(test_case["expected_message"])

            # Decrypt the secret
            secret = decrypt_secret_blob(secret_blob, password)

            # Encode the message (will produce different cover text due to random nonce)
            cover_text = encode_message(
                original_message, secret, client, prompt=prompt, compress=True
            )

            # Decode it back - this should produce the original message
            decoded = decode_message(cover_text, secret, client, prompt=prompt)

            assert decoded == original_message, (
                f"Roundtrip mismatch\n"
                f"Expected: {original_message!r}\n"
                f"Got: {decoded!r}"
            )


class TestFixedClientDeterminism:
    """Tests verifying FixedDistributionClient produces deterministic output."""

    def test_distribution_is_deterministic(self):
        """Verify FixedDistributionClient returns same distribution each call."""
        client = FixedDistributionClient(vocab_size=32)

        # Get distribution multiple times
        dist1 = client.get_token_distribution("context 1")
        dist2 = client.get_token_distribution("context 1")
        dist3 = client.get_token_distribution("different context")

        # All should be identical (context is ignored)
        for d1, d2, d3 in zip(dist1, dist2, dist3):
            assert d1.token == d2.token == d3.token
            assert d1.prob == d2.prob == d3.prob

    def test_encoding_produces_valid_decodable_output(self):
        """Verify encoding produces output that can be decoded.

        Note: Output is NOT identical across calls because AES-GCM uses random
        nonces. However, both outputs should decode to the same message.
        """
        client = FixedDistributionClient(vocab_size=32)
        secret = generate_secret(k=16, knock=[0, 1, 2, 3, 4, 5])
        message = b"Test message"
        prompt = "Test: "

        # Encode twice (will produce different cover text due to random nonces)
        cover1 = encode_message(message, secret, client, prompt=prompt)
        cover2 = encode_message(message, secret, client, prompt=prompt)

        # Both should decode to the original message
        decoded1 = decode_message(cover1, secret, client, prompt=prompt)
        decoded2 = decode_message(cover2, secret, client, prompt=prompt)

        assert decoded1 == message
        assert decoded2 == message

    def test_fixed_distribution_values(self):
        """Verify FixedDistributionClient returns expected values."""
        client = FixedDistributionClient(vocab_size=32)
        dist = client.get_token_distribution("any context")

        assert len(dist) == 32

        # Check first few tokens match expected
        assert dist[0].token == " the"
        assert abs(dist[0].prob - 0.12) < 0.001

        assert dist[1].token == " a"
        assert abs(dist[1].prob - 0.10) < 0.001

    def test_distribution_context_independent(self):
        """Verify distribution is the same for any context."""
        client = FixedDistributionClient(vocab_size=32)

        dist1 = client.get_token_distribution("")
        dist2 = client.get_token_distribution("Hello world")
        dist3 = client.get_token_distribution("Different context entirely")

        for d1, d2, d3 in zip(dist1, dist2, dist3):
            assert d1.token == d2.token == d3.token
            assert d1.prob == d2.prob == d3.prob


class TestStegoRoundtrip:
    """Tests for Python-only roundtrip with FixedDistributionClient."""

    def test_roundtrip_with_compression(self):
        """Verify encode/decode roundtrip works with compression."""
        client = FixedDistributionClient(vocab_size=32)
        secret = generate_secret(
            k=16,
            knock=[0, 1, 2, 3, 4, 5],
            preamble_tokens=5,
            suffix_tokens=5,
        )
        message = b"Hello, this is a test message for compression roundtrip."
        prompt = "Story: "

        cover_text = encode_message(message, secret, client, prompt=prompt, compress=True)
        decoded = decode_message(cover_text, secret, client, prompt=prompt)

        assert decoded == message

    def test_roundtrip_without_compression(self):
        """Verify encode/decode roundtrip works without compression."""
        client = FixedDistributionClient(vocab_size=32)
        secret = generate_secret(
            k=16,
            knock=[0, 1, 2, 3, 4, 5],
            preamble_tokens=5,
            suffix_tokens=5,
        )
        message = b"Short msg"
        prompt = "Note: "

        cover_text = encode_message(
            message, secret, client, prompt=prompt, compress=False
        )
        decoded = decode_message(cover_text, secret, client, prompt=prompt)

        assert decoded == message

    def test_roundtrip_various_messages(self):
        """Verify roundtrip works with various message types."""
        client = FixedDistributionClient(vocab_size=32)
        secret = generate_secret(
            k=16,
            knock=[0, 1, 2, 3, 4, 5],
            preamble_tokens=5,
            suffix_tokens=5,
        )
        prompt = "Test: "

        test_messages = [
            b"",  # Empty
            b"x",  # Single byte
            b"Hello",  # Short
            b"A" * 100,  # Repetitive
            bytes(range(256)),  # All byte values
            "Unicode: \u4e16\u754c".encode("utf-8"),  # UTF-8
        ]

        for message in test_messages:
            cover_text = encode_message(message, secret, client, prompt=prompt)
            decoded = decode_message(cover_text, secret, client, prompt=prompt)
            assert decoded == message, f"Roundtrip failed for: {message!r}"


class TestCrossLanguageSecrets:
    """Tests using secrets generated by the other language."""

    def test_use_ts_generated_secret(self, stego_roundtrip):
        """Verify Python can use secrets generated by TypeScript."""
        client = FixedDistributionClient(vocab_size=32)

        for test_case in stego_roundtrip.get("encoded", []):
            secret_blob = test_case["secret_blob"]
            password = test_case["password"]
            prompt = test_case["prompt"]

            # Decrypt the TS-generated secret
            secret = decrypt_secret_blob(secret_blob, password)

            # Use it to encode a new message
            new_message = b"New message encoded with TS secret"
            cover_text = encode_message(
                new_message, secret, client, prompt=prompt
            )

            # Decode it back
            decoded = decode_message(cover_text, secret, client, prompt=prompt)

            assert decoded == new_message
