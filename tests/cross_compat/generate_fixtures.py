#!/usr/bin/env python3
"""
Generate test fixtures for cross-compatibility testing.

This script generates JSON fixture files that can be used to verify
that TypeScript implementations produce identical results to Python.

Usage:
    python tests/cross_compat/generate_fixtures.py
"""

import base64
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lm_client import FixedDistributionClient
from stego_secret import (
    COMPRESSION_HUFFMAN,
    COMPRESSION_NONE,
    DEFAULT_FREQUENCIES,
    compress_payload,
    derive_key,
    encode_message,
    encrypt_payload,
    encrypt_secret_blob,
    generate_secret,
    huffman_encode,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def generate_crypto_vectors() -> dict:
    """Generate PBKDF2 and AES-GCM test vectors."""
    print("Generating crypto vectors...")

    pbkdf2_vectors = []

    # Test various password/salt combinations
    test_cases = [
        ("test123", b"0123456789abcdef"),
        ("password", b"saltsaltsaltsalt"),
        ("", b"emptypwd00000000"),  # Empty password
        ("long_password_with_special_chars!@#$%", b"anothersalt12345"),
        ("\u4e16\u754c", b"unicodepw1234567"),  # Unicode password
    ]

    for password, salt in test_cases:
        key = derive_key(password, salt)
        pbkdf2_vectors.append(
            {
                "password": password,
                "salt": base64.b64encode(salt).decode(),
                "expected_key": base64.b64encode(key).decode(),
            }
        )

    # Generate AES-GCM vectors
    aesgcm_vectors = []

    test_plaintexts = [
        b"Hello, World!",
        b"",  # Empty
        b"\x00\xff" * 10,  # Binary
        "Unicode: \u4e16\u754c".encode("utf-8"),
        b"A" * 1000,  # Larger payload
    ]

    for plaintext in test_plaintexts:
        # Use a fixed key for reproducibility
        key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
        ciphertext = encrypt_payload(plaintext, key)

        aesgcm_vectors.append(
            {
                "key": base64.b64encode(key).decode(),
                "plaintext": base64.b64encode(plaintext).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
        )

    return {
        "pbkdf2_vectors": pbkdf2_vectors,
        "aesgcm_vectors": aesgcm_vectors,
    }


def generate_secret_blobs() -> dict:
    """Generate encrypted secret blob test data."""
    print("Generating secret blobs...")

    blobs = []

    # Test various secret configurations
    test_configs = [
        {
            "k": 16,
            "knock": [0, 1, 2, 3, 4, 5],
            "password": "test_password_123",
            "preamble_tokens": 10,
            "suffix_tokens": 10,
            "temperature": 0.8,
        },
        {
            "k": 8,
            "knock": [0, 1, 2, 3],
            "password": "short",
            "preamble_tokens": 5,
            "suffix_tokens": 5,
            "temperature": 0.5,
        },
        {
            "k": 32,
            "knock": [0, 5, 10, 15, 20, 25, 30],
            "password": "unicode_\u4e16\u754c",
            "preamble_tokens": 15,
            "suffix_tokens": 15,
            "temperature": 1.0,
        },
    ]

    for config in test_configs:
        secret = generate_secret(
            k=config["k"],
            knock=config["knock"],
            preamble_tokens=config["preamble_tokens"],
            suffix_tokens=config["suffix_tokens"],
            temperature=config["temperature"],
        )

        encrypted = encrypt_secret_blob(secret, config["password"])

        blobs.append(
            {
                "encrypted": encrypted,
                "password": config["password"],
                "expected": {
                    "version": secret["version"],
                    "k": secret["k"],
                    "knock": secret["knock"],
                    "preamble_tokens": secret["preamble_tokens"],
                    "suffix_tokens": secret["suffix_tokens"],
                    "temperature": secret["temperature"],
                    "payload_key_length": len(secret["payload_key"]),
                },
            }
        )

    return {"blobs": blobs}


def generate_huffman_data() -> dict:
    """Generate Huffman compression test data."""
    print("Generating Huffman data...")

    compressed = []

    # Test various data types
    test_data = [
        b"The quick brown fox jumps over the lazy dog.",
        b"Hello World" * 50,  # Repetitive
        b"\x00\xff" * 10,  # Binary
        "Unicode: \u4e16\u754c".encode("utf-8"),
        b"AAAAAAAAAA",  # Very repetitive
        b"",  # Empty
        bytes(range(32, 127)),  # Printable ASCII
    ]

    for data in test_data:
        comp_data, comp_type = compress_payload(data, DEFAULT_FREQUENCIES)

        compressed.append(
            {
                "original": base64.b64encode(data).decode(),
                "compressed": base64.b64encode(comp_data).decode(),
                "compression_type": comp_type,
            }
        )

    # Also include the default frequencies for verification
    return {
        "compressed": compressed,
        "default_frequencies": DEFAULT_FREQUENCIES,
    }


def generate_stego_roundtrip() -> dict:
    """Generate full stego encode/decode test data."""
    print("Generating stego roundtrip data...")

    client = FixedDistributionClient(vocab_size=32)
    encoded = []

    # Test various messages
    test_cases = [
        {
            "message": b"Secret message",
            "prompt": "Once upon a time",
            "password": "stego_test_123",
            "k": 16,
            "knock": [0, 1, 2, 3, 4, 5],
        },
        {
            "message": b"",  # Empty message
            "prompt": "Test: ",
            "password": "empty_test",
            "k": 16,
            "knock": [0, 1, 2, 3, 4, 5],
        },
        {
            "message": "Unicode \u4e16\u754c!".encode("utf-8"),
            "prompt": "Story time: ",
            "password": "unicode_pw",
            "k": 16,
            "knock": [0, 1, 2, 3, 4, 5],
        },
    ]

    for case in test_cases:
        secret = generate_secret(
            k=case["k"],
            knock=case["knock"],
            preamble_tokens=5,
            suffix_tokens=5,
            temperature=0.8,
        )

        # Encrypt the secret
        secret_blob = encrypt_secret_blob(secret, case["password"])

        # Encode the message
        cover_text = encode_message(
            case["message"],
            secret,
            client,
            prompt=case["prompt"],
            compress=True,
        )

        encoded.append(
            {
                "secret_blob": secret_blob,
                "password": case["password"],
                "prompt": case["prompt"],
                "cover_text": cover_text,
                "expected_message": base64.b64encode(case["message"]).decode(),
            }
        )

    return {"encoded": encoded}


def main():
    """Generate all fixture files."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Generate crypto vectors
    crypto_vectors = generate_crypto_vectors()
    with open(FIXTURES_DIR / "crypto_vectors.json", "w") as f:
        json.dump(crypto_vectors, f, indent=2)
    print(f"  -> {FIXTURES_DIR / 'crypto_vectors.json'}")

    # Generate secret blobs
    secret_blobs = generate_secret_blobs()
    with open(FIXTURES_DIR / "secret_blobs.json", "w") as f:
        json.dump(secret_blobs, f, indent=2)
    print(f"  -> {FIXTURES_DIR / 'secret_blobs.json'}")

    # Generate Huffman data
    huffman_data = generate_huffman_data()
    with open(FIXTURES_DIR / "huffman_data.json", "w") as f:
        json.dump(huffman_data, f, indent=2)
    print(f"  -> {FIXTURES_DIR / 'huffman_data.json'}")

    # Generate stego roundtrip data
    stego_roundtrip = generate_stego_roundtrip()
    with open(FIXTURES_DIR / "stego_roundtrip.json", "w") as f:
        json.dump(stego_roundtrip, f, indent=2)
    print(f"  -> {FIXTURES_DIR / 'stego_roundtrip.json'}")

    print("\nAll fixtures generated successfully!")
    print(f"Fixtures directory: {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
