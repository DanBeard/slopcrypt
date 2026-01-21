"""
Cross-compatibility tests for msgpack secret blob serialization.

Tests that Python and TypeScript implementations can read each other's
encrypted secret blobs.
"""

import base64

import pytest

from stego_secret import (
    PAYLOAD_KEY_SIZE,
    SECRET_VERSION,
    decrypt_secret_blob,
    encrypt_secret_blob,
    generate_secret,
    validate_secret,
)


class TestSecretBlobCompatibility:
    """Tests for secret blob encryption/decryption cross-compatibility."""

    def test_decrypt_ts_encrypted_blob(self, secret_blobs):
        """Verify Python can decrypt secret blobs encrypted by TypeScript."""
        for blob_data in secret_blobs.get("blobs", []):
            encrypted = blob_data["encrypted"]
            password = blob_data["password"]
            expected = blob_data["expected"]

            # Decrypt the blob
            secret = decrypt_secret_blob(encrypted, password)

            # Verify key fields match
            assert secret["version"] == expected["version"]
            assert secret["k"] == expected["k"]
            assert secret["knock"] == expected["knock"]
            assert secret["preamble_tokens"] == expected["preamble_tokens"]
            assert secret["suffix_tokens"] == expected["suffix_tokens"]
            assert abs(secret["temperature"] - expected["temperature"]) < 0.001

            # Verify payload_key is correct length
            assert isinstance(secret["payload_key"], bytes)
            assert len(secret["payload_key"]) == PAYLOAD_KEY_SIZE

            # Verify the secret passes validation
            validate_secret(secret)

    def test_decrypt_ts_blob_wrong_password_fails(self, secret_blobs):
        """Verify decryption fails with wrong password."""
        for blob_data in secret_blobs.get("blobs", []):
            encrypted = blob_data["encrypted"]

            with pytest.raises(ValueError, match="[Dd]ecryption failed"):
                decrypt_secret_blob(encrypted, "wrong_password_12345")

    def test_encrypt_blob_for_ts_decryption(self, secret_blobs):
        """Generate encrypted blobs that TypeScript should be able to decrypt."""
        # This test generates blobs; the TypeScript tests verify decryption
        for blob_data in secret_blobs.get("blobs", []):
            password = blob_data["password"]

            # Create a secret with known values
            secret = generate_secret(
                k=16,
                knock=[0, 1, 2, 3, 4, 5],
                preamble_tokens=10,
                suffix_tokens=10,
                temperature=0.8,
            )

            # Encrypt it
            encrypted = encrypt_secret_blob(secret, password)

            # Verify we can decrypt our own blob
            decrypted = decrypt_secret_blob(encrypted, password)
            assert decrypted == secret


class TestSecretStructure:
    """Tests for secret structure compatibility."""

    def test_secret_version_constant(self, secret_blobs):
        """Verify secret version matches between implementations."""
        for blob_data in secret_blobs.get("blobs", []):
            assert blob_data["expected"]["version"] == SECRET_VERSION

    def test_payload_key_as_bytes(self, secret_blobs):
        """Verify payload_key is properly handled as binary."""
        for blob_data in secret_blobs.get("blobs", []):
            encrypted = blob_data["encrypted"]
            password = blob_data["password"]

            secret = decrypt_secret_blob(encrypted, password)

            # payload_key should be bytes, not a list or base64 string
            assert isinstance(secret["payload_key"], bytes)
            assert len(secret["payload_key"]) == 32

    def test_huffman_freq_as_dict(self, secret_blobs):
        """Verify huffman_freq is a dict with int keys."""
        for blob_data in secret_blobs.get("blobs", []):
            encrypted = blob_data["encrypted"]
            password = blob_data["password"]

            secret = decrypt_secret_blob(encrypted, password)

            if "huffman_freq" in secret:
                freq = secret["huffman_freq"]
                assert isinstance(freq, dict)
                # All keys should be integers (byte values)
                for key in freq.keys():
                    assert isinstance(key, int)
                    assert 0 <= key <= 255


class TestSecretRoundtrip:
    """Tests for full secret roundtrip between implementations."""

    def test_roundtrip_with_all_fields(self):
        """Verify all fields survive encrypt/decrypt roundtrip."""
        secret = generate_secret(
            k=16,
            knock=[1, 2, 3, 4, 5, 6],
            preamble_tokens=15,
            suffix_tokens=20,
            temperature=0.9,
            notes="Test note for cross-compat",
        )

        password = "test_roundtrip_password"
        encrypted = encrypt_secret_blob(secret, password)
        decrypted = decrypt_secret_blob(encrypted, password)

        assert decrypted == secret

    def test_roundtrip_with_minimal_fields(self):
        """Verify minimal required fields survive roundtrip."""
        secret = {
            "version": SECRET_VERSION,
            "k": 16,
            "knock": [0, 1],
            "payload_key": b"0" * 32,
            "preamble_tokens": 10,
            "suffix_tokens": 10,
            "temperature": 0.8,
            "huffman_freq": {},
            "notes": "",
        }

        password = "minimal_test"
        encrypted = encrypt_secret_blob(secret, password)
        decrypted = decrypt_secret_blob(encrypted, password)

        assert decrypted == secret
