"""
Cross-compatibility tests for cryptographic operations.

Tests that Python and TypeScript implementations produce identical results for:
- PBKDF2 key derivation
- AES-256-GCM encryption/decryption
"""

import base64

import pytest

from stego_secret import (
    PAYLOAD_KEY_SIZE,
    decrypt_payload,
    derive_key,
    encrypt_payload,
)


class TestPBKDF2Compatibility:
    """Tests for PBKDF2 key derivation cross-compatibility."""

    def test_pbkdf2_known_vectors(self, crypto_vectors):
        """Verify Python derives same PBKDF2 keys as fixtures."""
        for vector in crypto_vectors.get("pbkdf2_vectors", []):
            salt = base64.b64decode(vector["salt"])
            expected_key = base64.b64decode(vector["expected_key"])

            derived_key = derive_key(vector["password"], salt)

            assert derived_key == expected_key, (
                f"PBKDF2 key mismatch for password='{vector['password']}'\n"
                f"Expected: {vector['expected_key']}\n"
                f"Got: {base64.b64encode(derived_key).decode()}"
            )

    def test_pbkdf2_empty_password(self, crypto_vectors):
        """Verify empty password handling matches."""
        for vector in crypto_vectors.get("pbkdf2_vectors", []):
            if vector["password"] == "":
                salt = base64.b64decode(vector["salt"])
                expected_key = base64.b64decode(vector["expected_key"])
                derived_key = derive_key("", salt)
                assert derived_key == expected_key


class TestAESGCMCompatibility:
    """Tests for AES-256-GCM encryption/decryption cross-compatibility."""

    def test_decrypt_ts_encrypted_payload(self, crypto_vectors):
        """Verify Python can decrypt payloads encrypted by TypeScript."""
        for vector in crypto_vectors.get("aesgcm_vectors", []):
            key = base64.b64decode(vector["key"])
            ciphertext = base64.b64decode(vector["ciphertext"])
            expected_plaintext = base64.b64decode(vector["plaintext"])

            # The ciphertext includes nonce as required by decrypt_payload
            decrypted = decrypt_payload(ciphertext, key)

            assert decrypted == expected_plaintext, (
                f"AES-GCM decryption mismatch\n"
                f"Expected: {expected_plaintext!r}\n"
                f"Got: {decrypted!r}"
            )

    def test_encrypt_decrypt_roundtrip_with_ts_key(self, crypto_vectors):
        """Verify roundtrip using keys from TypeScript."""
        for vector in crypto_vectors.get("aesgcm_vectors", []):
            key = base64.b64decode(vector["key"])
            original = base64.b64decode(vector["plaintext"])

            # Encrypt in Python
            encrypted = encrypt_payload(original, key)

            # Decrypt in Python (verifies our own roundtrip works)
            decrypted = decrypt_payload(encrypted, key)

            assert decrypted == original


class TestPayloadKeyCompatibility:
    """Tests for payload encryption key handling."""

    def test_payload_key_size(self):
        """Verify payload key size matches between implementations."""
        # This constant must be the same in both Python and TypeScript
        assert PAYLOAD_KEY_SIZE == 32

    def test_decrypt_with_random_key_fails(self, crypto_vectors):
        """Verify decryption with wrong key fails."""
        import secrets

        for vector in crypto_vectors.get("aesgcm_vectors", []):
            ciphertext = base64.b64decode(vector["ciphertext"])
            wrong_key = secrets.token_bytes(PAYLOAD_KEY_SIZE)

            with pytest.raises(ValueError, match="decryption failed"):
                decrypt_payload(ciphertext, wrong_key)
