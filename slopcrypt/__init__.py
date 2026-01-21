"""
SlopCrypt - Hide your data in slop!

LLM steganography that embeds binary data in AI-generated text.
Each token encodes log2(K) bits by picking from the top-K most probable tokens.

Example usage:
    from slopcrypt import encode_message, decode_message, generate_secret
    from slopcrypt.lm_client import MockLMClient

    # Generate a secret
    secret = generate_secret(k=16)

    # Encode a message
    client = MockLMClient()
    cover_text = encode_message(b"Secret!", secret, client)

    # Decode the message
    decoded = decode_message(cover_text, secret, client)
"""

# Core encoding/decoding functions
from slopcrypt.encode import (
    DEFAULT_K,
    DEFAULT_PROMPT,
    decode,
    decode_with_knock,
    encode,
    encode_with_knock,
)

# Secret management
from slopcrypt.secret import (
    NONCE_SIZE,
    PAYLOAD_KEY_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    SECRET_VERSION,
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

# Compression
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

# Utilities
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

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Core encoding
    "encode",
    "decode",
    "encode_with_knock",
    "decode_with_knock",
    "DEFAULT_K",
    "DEFAULT_PROMPT",
    # High-level API
    "encode_message",
    "decode_message",
    # Secret management
    "generate_secret",
    "save_secret",
    "load_secret",
    "validate_secret",
    "generate_random_knock",
    "derive_key",
    "encrypt_secret_blob",
    "decrypt_secret_blob",
    "encrypt_payload",
    "decrypt_payload",
    "SECRET_VERSION",
    "PBKDF2_ITERATIONS",
    "SALT_SIZE",
    "NONCE_SIZE",
    "PAYLOAD_KEY_SIZE",
    # Compression
    "compress_payload",
    "decompress_payload",
    "huffman_encode",
    "huffman_decode",
    "arithmetic_encode",
    "arithmetic_decode",
    "build_huffman_tree",
    "get_huffman_codes",
    "build_frequency_table",
    "HuffmanNode",
    "ArithmeticEncoder",
    "ArithmeticDecoder",
    "COMPRESSION_NONE",
    "COMPRESSION_HUFFMAN",
    "COMPRESSION_ARITHMETIC",
    "DEFAULT_FREQUENCIES",
    # Utilities
    "TokenProb",
    "bytes_to_bits",
    "bits_to_bytes",
    "bits_to_int",
    "int_to_bits",
    "filter_prefix_tokens",
    "find_longest_match",
    "parse_knock_sequence",
    "find_knock_sequence",
    "check_knock_in_data",
]
