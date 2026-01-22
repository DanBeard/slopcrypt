#!/usr/bin/env python3
"""
Tests for SlopCrypt secret management (slopcrypt.secret).

Run with: python -m pytest tests/test_secret.py -v
"""

import os
import tempfile

import pytest

from slopcrypt.compress import (
    COMPRESSION_ARITHMETIC,
    COMPRESSION_HUFFMAN,
    COMPRESSION_NONE,
    DEFAULT_FREQUENCIES,
    arithmetic_decode,
    arithmetic_encode,
    build_frequency_table,
    build_huffman_tree,
    compress_payload,
    decompress_payload,
    get_huffman_codes,
    huffman_decode,
    huffman_encode,
)
from slopcrypt.lm_client import MockLMClient
from slopcrypt.secret import (
    PAYLOAD_KEY_SIZE,
    decode_message,
    decrypt_payload,
    decrypt_secret_blob,
    derive_key,
    encode_message,
    encrypt_payload,
    encrypt_secret_blob,
    generate_random_knock,
    generate_secret,
    load_secret,
    save_secret,
    validate_secret,
)


class TestCrypto:
    """Tests for Crypto & Secret Management."""

    def test_derive_key_deterministic(self):
        """Same password and salt should produce same key."""
        salt = b"0123456789abcdef"
        key1 = derive_key("password123", salt)
        key2 = derive_key("password123", salt)
        assert key1 == key2
        assert len(key1) == 32  # 256 bits

    def test_derive_key_different_passwords(self):
        """Different passwords should produce different keys."""
        salt = b"0123456789abcdef"
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_different_salts(self):
        """Different salts should produce different keys."""
        key1 = derive_key("password", b"salt1234salt1234")
        key2 = derive_key("password", b"salt5678salt5678")
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original data."""
        secret = {
            "version": 2,
            "knock": [1, 2, 3],
            "k": 16,
            "payload_key": b"0" * 32,
        }
        password = "test_password"

        encrypted = encrypt_secret_blob(secret, password)
        decrypted = decrypt_secret_blob(encrypted, password)

        assert decrypted == secret

    def test_decrypt_wrong_password(self):
        """Decryption with wrong password should fail."""
        secret = {"version": 2, "knock": [1], "k": 16, "payload_key": b"0" * 32}
        encrypted = encrypt_secret_blob(secret, "correct_password")

        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_secret_blob(encrypted, "wrong_password")

    def test_decrypt_corrupted_blob(self):
        """Decryption of corrupted blob should fail."""
        secret = {"version": 2, "knock": [1], "k": 16, "payload_key": b"0" * 32}
        encrypted = encrypt_secret_blob(secret, "password")

        # Corrupt the blob
        corrupted = encrypted[:-5] + "XXXXX"

        with pytest.raises(ValueError):
            decrypt_secret_blob(corrupted, "password")

    def test_generate_random_knock(self):
        """Random knock should have correct length and range."""
        knock = generate_random_knock(k=16, length=6)
        assert len(knock) == 6
        assert all(0 <= idx < 16 for idx in knock)

    def test_generate_random_knock_different_k(self):
        """Knock indices should respect K value."""
        knock = generate_random_knock(k=4, length=10)
        assert len(knock) == 10
        assert all(0 <= idx < 4 for idx in knock)

    def test_validate_secret_valid(self):
        """Valid secret should pass validation."""
        secret = {
            "version": 2,
            "knock": [1, 2, 3, 4],
            "k": 16,
            "payload_key": b"0" * 32,
        }
        validate_secret(secret)  # Should not raise

    def test_validate_secret_missing_field(self):
        """Missing required field should fail validation."""
        secret = {"version": 2, "knock": [1, 2], "k": 16}  # Missing payload_key
        with pytest.raises(ValueError, match="Missing required field"):
            validate_secret(secret)

    def test_validate_secret_invalid_k(self):
        """Non-power-of-2 K should fail validation."""
        secret = {"version": 2, "knock": [1], "k": 15, "payload_key": b"0" * 32}
        with pytest.raises(ValueError, match="K must be a power of 2"):
            validate_secret(secret)

    def test_validate_secret_knock_out_of_range(self):
        """Knock index >= K should fail validation."""
        secret = {"version": 2, "knock": [1, 20], "k": 16, "payload_key": b"0" * 32}
        with pytest.raises(ValueError, match="must be in"):
            validate_secret(secret)

    def test_generate_secret_auto_knock(self):
        """Generate secret should auto-create knock if not specified."""
        secret = generate_secret(k=16)
        assert "knock" in secret
        assert len(secret["knock"]) == 6  # Default length
        assert all(0 <= idx < 16 for idx in secret["knock"])

    def test_generate_secret_explicit_knock(self):
        """Generate secret should use provided knock."""
        knock = [1, 5, 9, 13]
        secret = generate_secret(k=16, knock=knock)
        assert secret["knock"] == knock

    def test_generate_secret_has_payload_key(self):
        """Generate secret should include random payload key."""
        secret = generate_secret(k=16)
        assert "payload_key" in secret
        assert isinstance(secret["payload_key"], bytes)
        assert len(secret["payload_key"]) == PAYLOAD_KEY_SIZE

    def test_encrypt_decrypt_payload_roundtrip(self):
        """Encrypt then decrypt payload should return original data."""
        key = b"0" * PAYLOAD_KEY_SIZE
        data = b"Secret payload data"

        encrypted = encrypt_payload(data, key)
        decrypted = decrypt_payload(encrypted, key)

        assert decrypted == data

    def test_decrypt_payload_wrong_key(self):
        """Decrypting with wrong key should fail."""
        key1 = b"0" * PAYLOAD_KEY_SIZE
        key2 = b"1" * PAYLOAD_KEY_SIZE
        data = b"Secret data"

        encrypted = encrypt_payload(data, key1)

        with pytest.raises(ValueError, match="decryption failed"):
            decrypt_payload(encrypted, key2)

    def test_save_load_secret(self):
        """Save and load should roundtrip correctly."""
        secret = generate_secret(k=16)
        password = "test123"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".secret", delete=False) as f:
            path = f.name

        try:
            save_secret(secret, password, path)
            loaded = load_secret(path, password)
            assert loaded == secret
        finally:
            os.unlink(path)


class TestHuffman:
    """Tests for Huffman Compression."""

    def test_build_huffman_tree(self):
        """Should build valid Huffman tree."""
        freq = {ord("a"): 5, ord("b"): 9, ord("c"): 12}
        tree = build_huffman_tree(freq)
        assert tree is not None
        assert tree.freq == 26  # Sum of all frequencies

    def test_get_huffman_codes(self):
        """Should generate valid codes for each byte."""
        freq = {ord("a"): 5, ord("b"): 9, ord("c"): 12}
        codes = get_huffman_codes(freq)
        assert len(codes) == 3
        # All codes should be unique
        assert len(set(codes.values())) == 3
        # All codes should be binary strings
        assert all(set(code).issubset({"0", "1"}) for code in codes.values())

    def test_huffman_encode_decode_roundtrip(self):
        """Encode then decode should return original data."""
        data = b"hello world"
        freq = build_frequency_table(data)

        encoded = huffman_encode(data, freq)
        decoded = huffman_decode(encoded, freq)

        assert decoded == data

    def test_huffman_encode_decode_english(self):
        """Should work with default English frequencies."""
        data = b"The quick brown fox jumps over the lazy dog."

        encoded = huffman_encode(data, DEFAULT_FREQUENCIES)
        decoded = huffman_decode(encoded, DEFAULT_FREQUENCIES)

        assert decoded == data

    def test_huffman_compression_ratio(self):
        """English text should compress to ~50-60% of original."""
        data = b"The quick brown fox jumps over the lazy dog. " * 10

        encoded = huffman_encode(data, DEFAULT_FREQUENCIES)
        ratio = len(encoded) / len(data)

        # Should be noticeably smaller (typically 50-70%)
        assert ratio < 0.8

    def test_compress_payload_huffman(self):
        """Text data should use Huffman compression."""
        data = b"Hello world, this is a test message for compression."

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)

        assert comp_type == COMPRESSION_HUFFMAN
        assert len(compressed) < len(data)

    def test_compress_payload_none_for_random(self):
        """Random binary data may not compress well."""
        # Highly random data won't compress well
        data = bytes(range(256))  # All possible byte values

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)

        # Either raw or Huffman depending on data
        assert comp_type in (COMPRESSION_NONE, COMPRESSION_HUFFMAN)

    def test_decompress_payload_roundtrip(self):
        """Compress then decompress should return original."""
        data = b"Test message for compression roundtrip"

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)
        decompressed = decompress_payload(compressed, comp_type, DEFAULT_FREQUENCIES)

        assert decompressed == data

    def test_decompress_none(self):
        """COMPRESSION_NONE should return data unchanged."""
        data = b"raw data"
        result = decompress_payload(data, COMPRESSION_NONE, DEFAULT_FREQUENCIES)
        assert result == data

    def test_build_frequency_table(self):
        """Should build frequency table from sample."""
        sample = b"aaabbc"
        freq = build_frequency_table(sample)

        assert freq[ord("a")] == 3
        assert freq[ord("b")] == 2
        assert freq[ord("c")] == 1
        # Printable ASCII should have at least 1
        assert freq.get(ord("z"), 0) >= 1


class TestArithmeticCoding:
    """Tests for Arithmetic Coding Compression."""

    def test_arithmetic_encode_decode_roundtrip(self):
        """Encode then decode should return original data."""
        data = b"hello world"
        freq = build_frequency_table(data)

        encoded = arithmetic_encode(data, freq)
        decoded = arithmetic_decode(encoded, freq)

        assert decoded == data

    def test_arithmetic_encode_decode_english(self):
        """Should work with default English frequencies."""
        data = b"The quick brown fox jumps over the lazy dog."

        encoded = arithmetic_encode(data, DEFAULT_FREQUENCIES)
        decoded = arithmetic_decode(encoded, DEFAULT_FREQUENCIES)

        assert decoded == data

    def test_arithmetic_compression_ratio(self):
        """Arithmetic coding should compress better than Huffman."""
        data = b"The quick brown fox jumps over the lazy dog. " * 10

        arith_encoded = arithmetic_encode(data, DEFAULT_FREQUENCIES)
        huffman_encoded = huffman_encode(data, DEFAULT_FREQUENCIES)

        arith_ratio = len(arith_encoded) / len(data)
        huffman_ratio = len(huffman_encoded) / len(data)

        # Arithmetic should compress better (or at least as well)
        assert arith_ratio <= huffman_ratio + 0.05, (
            f"Arithmetic ratio {arith_ratio:.3f} should be <= Huffman ratio {huffman_ratio:.3f}"
        )

    def test_arithmetic_empty_data(self):
        """Should handle empty data."""
        data = b""
        encoded = arithmetic_encode(data, DEFAULT_FREQUENCIES)
        decoded = arithmetic_decode(encoded, DEFAULT_FREQUENCIES)

        assert decoded == data

    def test_arithmetic_single_byte(self):
        """Should handle single byte."""
        data = b"x"
        encoded = arithmetic_encode(data, DEFAULT_FREQUENCIES)
        decoded = arithmetic_decode(encoded, DEFAULT_FREQUENCIES)

        assert decoded == data

    def test_arithmetic_repeated_bytes(self):
        """Should handle repeated bytes efficiently."""
        data = b"aaaaaaaaaa"  # 10 'a' characters
        freq = {ord("a"): 100, ord("b"): 1}

        encoded = arithmetic_encode(data, freq)
        decoded = arithmetic_decode(encoded, freq)

        assert decoded == data
        # With very skewed frequencies, highly repeated data should compress well
        # 10 bytes of 'a' with 100:1 frequency ratio should compress significantly
        assert len(encoded) < len(data)

    def test_compress_payload_uses_arithmetic_for_text(self):
        """Long English text should use arithmetic coding."""
        # Longer text to ensure arithmetic coding wins
        data = b"The quick brown fox jumps over the lazy dog. " * 20

        compressed, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)

        # Should use arithmetic coding for English text (better compression)
        assert comp_type == COMPRESSION_ARITHMETIC
        assert len(compressed) < len(data)

    def test_decompress_payload_arithmetic(self):
        """Should correctly decompress arithmetic-coded data."""
        data = b"Test message for arithmetic compression roundtrip"
        encoded = arithmetic_encode(data, DEFAULT_FREQUENCIES)

        decompressed = decompress_payload(encoded, COMPRESSION_ARITHMETIC, DEFAULT_FREQUENCIES)

        assert decompressed == data

    def test_arithmetic_vs_huffman_comparison(self):
        """Compare arithmetic vs Huffman compression ratios."""
        test_texts = [
            b"The quick brown fox jumps over the lazy dog.",
            b"To be or not to be, that is the question.",
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            b"AAAA" * 50,  # Highly compressible
        ]

        for data in test_texts:
            arith = arithmetic_encode(data, DEFAULT_FREQUENCIES)
            huffman = huffman_encode(data, DEFAULT_FREQUENCIES)

            # Both should roundtrip correctly
            assert arithmetic_decode(arith, DEFAULT_FREQUENCIES) == data
            assert huffman_decode(huffman, DEFAULT_FREQUENCIES) == data


class TestEncodeDecodeWrappers:
    """Tests for Encode/Decode Wrappers."""

    @pytest.fixture
    def mock_client(self):
        """Create mock LLM client."""
        return MockLMClient(vocab_size=32)

    @pytest.fixture
    def secret(self):
        """Create test secret."""
        return generate_secret(
            k=16,
            knock=[1, 5, 9, 13, 2, 6],
            preamble_tokens=5,
            suffix_tokens=5,
        )

    def test_encode_decode_roundtrip(self, mock_client, secret):
        """Encode then decode should return original message."""
        message = b"Hello World"
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message

    def test_encode_decode_with_compression(self, mock_client, secret):
        """Should work with Huffman compression enabled."""
        message = b"This is a longer test message that should compress well with Huffman encoding."
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt, compress=True)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message

    def test_encode_decode_without_compression(self, mock_client, secret):
        """Should work with compression disabled."""
        message = b"Test without compression"
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt, compress=False)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message

    def test_encode_decode_empty_message(self, mock_client, secret):
        """Should handle empty message."""
        message = b""
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message

    def test_encode_decode_binary_data(self, mock_client, secret):
        """Should handle binary data."""
        message = bytes(range(256))  # All byte values
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt, compress=False)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message

    def test_encode_decode_unicode_text(self, mock_client, secret):
        """Should handle UTF-8 encoded text."""
        message = "Hello, \u4e16\u754c! \U0001f600".encode()
        prompt = "Test: "

        cover_text = encode_message(message, secret, mock_client, prompt=prompt)
        decoded = decode_message(cover_text, secret, mock_client, prompt=prompt)

        assert decoded == message


class TestIntegration:
    """Integration tests combining all components."""

    def test_full_workflow(self):
        """Test complete workflow: generate secret, encode, decode."""
        # Generate secret (prompt specified at encode time, not in secret)
        secret = generate_secret(
            k=16,
            preamble_tokens=8,
            suffix_tokens=8,
        )

        # Encrypt and save
        password = "integration_test_password"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".secret", delete=False) as f:
            path = f.name

        try:
            save_secret(secret, password, path)

            # Load back
            loaded_secret = load_secret(path, password)
            assert loaded_secret == secret

            # Create client
            client = MockLMClient(vocab_size=32)

            # Encode message (prompt specified here, not in secret)
            message = b"This is a secret message for the integration test."
            prompt = "Once upon a time in a land far away, there lived"
            cover_text = encode_message(message, loaded_secret, client, prompt=prompt)

            # Decode message (prompt needed for correct context alignment)
            decoded = decode_message(cover_text, loaded_secret, client, prompt=prompt)

            assert decoded == message

        finally:
            os.unlink(path)

    def test_different_k_values(self):
        """Test with various K values."""
        client = MockLMClient(vocab_size=64)
        message = b"Test message"
        prompt = "Test: "

        # Use explicit knocks that are unlikely to appear in random encrypted data
        # Longer sequences with varied patterns are less likely to collide
        knocks_by_k = {
            4: [3, 0, 3, 0, 3, 1, 2, 1],  # Longer pattern less likely in payload
            8: [7, 0, 7, 0, 5, 2, 6, 3],
            16: [15, 0, 14, 1, 13, 2, 12, 3],
        }
        for k in [4, 8, 16]:
            knock = knocks_by_k[k]
            secret = generate_secret(k=k, knock=knock)

            cover_text = encode_message(message, secret, client, prompt=prompt)
            decoded = decode_message(cover_text, secret, client, prompt=prompt)

            assert decoded == message, f"Failed for K={k}"

    def test_wrong_secret_fails(self):
        """Decoding with wrong secret should fail or return garbage."""
        client = MockLMClient(vocab_size=32)
        message = b"Secret message"
        prompt = "Test: "

        secret1 = generate_secret(k=16, knock=[1, 2, 3, 4, 5, 6])
        secret2 = generate_secret(k=16, knock=[6, 5, 4, 3, 2, 1])

        cover_text = encode_message(message, secret1, client, prompt=prompt)

        # Decoding with wrong knock should fail to find knock sequence
        with pytest.raises(ValueError, match="[Kk]nock"):
            decode_message(cover_text, secret2, client, prompt=prompt)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
