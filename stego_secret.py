#!/usr/bin/env python3
"""
DEPRECATED: Use 'from slopcrypt import ...' or 'python -m slopcrypt.secret' instead.

This module is a compatibility wrapper that re-exports from slopcrypt.
It will be removed in a future version.
"""
import warnings

warnings.warn(
    "stego_secret.py is deprecated. Use 'from slopcrypt import ...' "
    "or 'python -m slopcrypt.secret' instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from slopcrypt modules for backwards compatibility
from slopcrypt.compress import (
    COMPRESSION_ARITHMETIC,
    COMPRESSION_HUFFMAN,
    COMPRESSION_NONE,
    DEFAULT_FREQUENCIES,
    ArithmeticDecoder,
    ArithmeticEncoder,
    HuffmanNode,
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
from slopcrypt.secret import (
    DEFAULT_PROMPT,
    NONCE_SIZE,
    PAYLOAD_KEY_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    SECRET_VERSION,
    cmd_decode,
    cmd_encode,
    cmd_generate_secret,
    cmd_show_secret,
    create_client,
    decode_message,
    decrypt_payload,
    decrypt_secret_blob,
    derive_key,
    encode_message,
    encrypt_payload,
    encrypt_secret_blob,
    generate_random_knock,
    generate_secret,
    get_password,
    load_secret,
    main,
    save_secret,
    validate_secret,
)

__all__ = [
    # Compression constants
    "COMPRESSION_NONE",
    "COMPRESSION_HUFFMAN",
    "COMPRESSION_ARITHMETIC",
    "DEFAULT_FREQUENCIES",
    # Huffman
    "HuffmanNode",
    "build_huffman_tree",
    "get_huffman_codes",
    "huffman_encode",
    "huffman_decode",
    # Arithmetic
    "ArithmeticEncoder",
    "ArithmeticDecoder",
    "arithmetic_encode",
    "arithmetic_decode",
    # Compression API
    "compress_payload",
    "decompress_payload",
    "build_frequency_table",
    # Secret management constants
    "PBKDF2_ITERATIONS",
    "SALT_SIZE",
    "NONCE_SIZE",
    "PAYLOAD_KEY_SIZE",
    "SECRET_VERSION",
    "DEFAULT_PROMPT",
    # Secret management
    "derive_key",
    "encrypt_secret_blob",
    "decrypt_secret_blob",
    "generate_random_knock",
    "validate_secret",
    "encrypt_payload",
    "decrypt_payload",
    "generate_secret",
    "save_secret",
    "load_secret",
    # Message encode/decode
    "encode_message",
    "decode_message",
    # CLI
    "get_password",
    "create_client",
    "cmd_generate_secret",
    "cmd_encode",
    "cmd_decode",
    "cmd_show_secret",
    "main",
]

if __name__ == "__main__":
    main()
