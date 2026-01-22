#!/usr/bin/env python3
"""
SlopCrypt - Encrypted Secret Wrapper for LLM Steganography

Wraps slopcrypt.encode with:
- Encrypted out-of-band secret blob (base64 msgpack)
- Password-derived symmetric encryption (PBKDF2 + AES-256-GCM)
- Custom Huffman compression (frequency table stored in secret)

Usage:
    # Generate secret (auto-generates random knock)
    python -m slopcrypt.secret generate-secret -o my.secret --k 16 --prompt "Once upon a time"

    # Encode
    echo "Secret message" | python -m slopcrypt.secret encode --secret my.secret --mock

    # Decode
    python -m slopcrypt.secret decode --secret my.secret --mock -i cover.txt
"""

import argparse
import base64
import getpass
import math
import secrets
import sys

import msgpack
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from slopcrypt.compress import (
    COMPRESSION_HUFFMAN,
    COMPRESSION_NONE,
    DEFAULT_FREQUENCIES,
    build_frequency_table,
    compress_payload,
    decompress_payload,
)
from slopcrypt.encode import decode_with_knock_arithmetic, encode_with_knock_arithmetic
from slopcrypt.lm_client import (
    DEFAULT_MODEL_PATH,
    LlamaCppClient,
    LMClient,
    LMConfig,
    MockLMClient,
)

# ============================================================================
# Crypto & Secret Management
# ============================================================================

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
PAYLOAD_KEY_SIZE = 32  # AES-256
SECRET_VERSION = 2  # Bumped for payload encryption


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 256-bit key from password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_secret_blob(secret: dict, password: str) -> str:
    """
    Encrypt secret dict and return base64-encoded blob.

    Format: base64([salt:16][nonce:12][ciphertext+tag])
    """
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    plaintext = msgpack.packb(secret, use_bin_type=True)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode("ascii")


def decrypt_secret_blob(blob_b64: str, password: str) -> dict:
    """
    Decrypt base64-encoded secret blob.

    Raises:
        ValueError: If decryption fails (wrong password or corrupted)
    """
    try:
        blob = base64.b64decode(blob_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}") from e

    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:  # 16 = minimum ciphertext + tag
        raise ValueError("Secret blob too short")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Decryption failed - wrong password or corrupted data") from e

    return msgpack.unpackb(plaintext, raw=False, strict_map_key=False)


def generate_random_knock(k: int, length: int = 6) -> list[int]:
    """Generate random knock sequence with values in [0, k)."""
    return [secrets.randbelow(k) for _ in range(length)]


def validate_secret(secret: dict) -> None:
    """
    Validate secret dict has required fields and valid values.

    Raises:
        ValueError: If validation fails
    """
    required = ["version", "knock", "k", "payload_key"]
    for field in required:
        if field not in secret:
            raise ValueError(f"Missing required field: {field}")

    if secret["version"] not in (1, SECRET_VERSION):
        raise ValueError(f"Unsupported secret version: {secret['version']}")

    k = secret["k"]
    if not isinstance(k, int) or k < 2 or (k & (k - 1)) != 0:
        raise ValueError(f"K must be a power of 2 >= 2, got {k}")

    knock = secret["knock"]
    if not isinstance(knock, list) or len(knock) < 1:
        raise ValueError("Knock sequence must be a non-empty list")

    for idx in knock:
        if not isinstance(idx, int) or idx < 0 or idx >= k:
            raise ValueError(f"Knock index {idx} must be in [0, {k})")

    # Validate payload key
    payload_key = secret["payload_key"]
    if not isinstance(payload_key, bytes) or len(payload_key) != PAYLOAD_KEY_SIZE:
        raise ValueError(f"payload_key must be {PAYLOAD_KEY_SIZE} bytes")


def encrypt_payload(data: bytes, key: bytes) -> bytes:
    """
    Encrypt payload data with AES-256-GCM.

    Returns: [nonce:12][ciphertext+tag]
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_payload(encrypted: bytes, key: bytes) -> bytes:
    """
    Decrypt payload data with AES-256-GCM.

    Args:
        encrypted: [nonce:12][ciphertext+tag]
        key: 32-byte key

    Raises:
        ValueError: If decryption fails
    """
    if len(encrypted) < NONCE_SIZE + 16:  # nonce + minimum tag
        raise ValueError("Encrypted payload too short")

    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Payload decryption failed - corrupted data or wrong key") from e


def generate_secret(
    k: int,
    knock: list[int] | None = None,
    preamble_tokens: int = 4,
    suffix_tokens: int = 2,
    temperature: float = 0.8,
    entropy_threshold: float = 0.0,
    huffman_sample: bytes | None = None,
    notes: str = "",
) -> dict:
    """
    Generate a new secret dict.

    Args:
        k: Number of tokens to choose from (must be power of 2)
        knock: Knock sequence (auto-generated if None)
        preamble_tokens: Natural tokens before knock
        suffix_tokens: Natural tokens after payload
        temperature: Sampling temperature for preamble/suffix
        entropy_threshold: If top token prob > this, skip encoding (0.0 = disabled)
        huffman_sample: Sample text to build frequency table (optional)
        notes: Optional metadata

    Returns:
        Secret dict ready for encryption
    """
    if knock is None:
        knock = generate_random_knock(k, length=6)

    # Build Huffman frequency table
    if huffman_sample:
        huffman_freq = build_frequency_table(huffman_sample)
    else:
        huffman_freq = DEFAULT_FREQUENCIES.copy()

    # Generate random payload encryption key
    payload_key = secrets.token_bytes(PAYLOAD_KEY_SIZE)

    secret = {
        "version": SECRET_VERSION,
        "knock": knock,
        "k": k,
        "payload_key": payload_key,
        "preamble_tokens": preamble_tokens,
        "suffix_tokens": suffix_tokens,
        "temperature": temperature,
        "entropy_threshold": entropy_threshold,
        "huffman_freq": huffman_freq,
        "notes": notes,
    }

    validate_secret(secret)
    return secret


def save_secret(secret: dict, password: str, path: str) -> None:
    """Encrypt and save secret to file."""
    blob = encrypt_secret_blob(secret, password)
    with open(path, "w") as f:
        f.write(blob)


def load_secret(path: str, password: str) -> dict:
    """Load and decrypt secret from file."""
    with open(path) as f:
        blob = f.read().strip()
    secret = decrypt_secret_blob(blob, password)
    validate_secret(secret)
    return secret


# ============================================================================
# Encode/Decode Wrappers
# ============================================================================

DEFAULT_PROMPT = "Write a short story about a traveler:\n\nThe weary traveler had been walking for"


def encode_message(
    message: bytes,
    secret: dict,
    client,
    prompt: str | None = None,
    compress: bool = True,
    verbose: bool = False,
) -> str:
    """
    Encode message using secret parameters.

    Flow: message → compress → encrypt → encode into cover text

    Args:
        message: Message to encode
        secret: Decrypted secret dict
        client: LLM client
        prompt: Initial prompt for cover text (uses default if not specified)
        compress: Whether to try Huffman compression
        verbose: Print progress

    Returns:
        Cover text containing hidden message
    """
    if prompt is None:
        prompt = DEFAULT_PROMPT

    frequencies = secret.get("huffman_freq", DEFAULT_FREQUENCIES)

    # Step 1: Compress if enabled
    if compress:
        compressed, comp_type = compress_payload(message, frequencies)
        if verbose and comp_type == COMPRESSION_HUFFMAN:
            ratio = len(compressed) / len(message) if message else 1.0
            print(
                f"Huffman compression: {len(message)} -> {len(compressed)} bytes ({ratio:.1%})",
                file=sys.stderr,
            )
    else:
        compressed = message
        comp_type = COMPRESSION_NONE

    # Prepend compression type byte
    compressed_with_header = bytes([comp_type]) + compressed

    # Step 2: Encrypt the compressed data
    payload_key = secret["payload_key"]
    encrypted = encrypt_payload(compressed_with_header, payload_key)

    if verbose:
        print(
            f"Encrypted payload: {len(encrypted)} bytes (from {len(compressed_with_header)} compressed)",
            file=sys.stderr,
        )

    payload = encrypted

    # Encode using arithmetic coding for provably secure steganography
    cover_text = encode_with_knock_arithmetic(
        data=payload,
        client=client,
        prompt=prompt,
        k=secret["k"],
        knock=secret["knock"],
        preamble_tokens=secret.get("preamble_tokens", 4),
        suffix_tokens=secret.get("suffix_tokens", 2),
        temperature=secret.get("temperature", 0.8),
        entropy_threshold=secret.get("entropy_threshold", 0.0),
        verbose=verbose,
    )

    return cover_text


def decode_message(
    cover_text: str,
    secret: dict,
    client,
    prompt: str | None = None,
    verbose: bool = False,
) -> bytes:
    """
    Decode message from cover text using secret parameters.

    Flow: decode from cover text → decrypt → decompress → message

    Args:
        cover_text: Cover text containing hidden message
        secret: Decrypted secret dict
        client: LLM client
        prompt: Prompt used during encoding (for correct context alignment)
        verbose: Print progress

    Returns:
        Decoded message
    """
    # Step 1: Decode using arithmetic coding
    encrypted_payload = decode_with_knock_arithmetic(
        cover_text=cover_text,
        client=client,
        k=secret["k"],
        knock=secret["knock"],
        prompt=prompt or "",
        entropy_threshold=secret.get("entropy_threshold", 0.0),
        verbose=verbose,
    )

    if len(encrypted_payload) < NONCE_SIZE + 16 + 1:  # nonce + tag + at least 1 byte
        raise ValueError("Decoded payload too short")

    # Step 2: Decrypt
    payload_key = secret["payload_key"]
    try:
        decrypted = decrypt_payload(encrypted_payload, payload_key)
    except ValueError as e:
        raise ValueError(f"Payload decryption failed: {e}") from e

    if verbose:
        print(f"Decrypted: {len(encrypted_payload)} -> {len(decrypted)} bytes", file=sys.stderr)

    if len(decrypted) < 1:
        raise ValueError("Decrypted payload too short")

    # Step 3: Extract compression type and decompress
    comp_type = decrypted[0]
    compressed = decrypted[1:]

    if verbose:
        print(f"Compression type: {comp_type}", file=sys.stderr)

    frequencies = secret.get("huffman_freq", DEFAULT_FREQUENCIES)
    message = decompress_payload(compressed, comp_type, frequencies)

    if verbose and comp_type == COMPRESSION_HUFFMAN:
        print(f"Decompressed: {len(compressed)} -> {len(message)} bytes", file=sys.stderr)

    return message


# ============================================================================
# CLI
# ============================================================================


def get_password(args, confirm: bool = False) -> str:
    """Get password from args or prompt."""
    if args.password:
        return args.password

    password = getpass.getpass("Password: ")

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            print("Passwords do not match", file=sys.stderr)
            sys.exit(1)

    return password


def create_client(args):
    """Create LLM client based on args."""
    if args.mock:
        return MockLMClient(vocab_size=max(32, 16))
    elif getattr(args, "mlx", False):
        if not args.mlx_model:
            print("--mlx-model required (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)", file=sys.stderr)
            sys.exit(1)
        from slopcrypt.lm_client import MLXClient

        return MLXClient(model_name=args.mlx_model, top_k=64)
    elif args.lmstudio:
        if not args.model:
            print("--model required for LM Studio", file=sys.stderr)
            sys.exit(1)
        config = LMConfig(host=args.host, model=args.model, top_logprobs=10)
        return LMClient(config)
    else:
        if not args.model_path:
            print("Model path required. Use --model-path, --mlx, --lmstudio, or --mock", file=sys.stderr)
            sys.exit(1)
        return LlamaCppClient(model_path=args.model_path, top_k=64)


def cmd_generate_secret(args):
    """Handle generate-secret command."""
    # Parse knock if provided
    knock = None
    if args.knock:
        try:
            knock = [int(x.strip()) for x in args.knock.split(",")]
            for idx in knock:
                if idx < 0 or idx >= args.k:
                    print(f"Knock index {idx} must be in [0, {args.k})", file=sys.stderr)
                    sys.exit(1)
        except ValueError as e:
            print(f"Invalid knock sequence: {e}", file=sys.stderr)
            sys.exit(1)

    # Load Huffman sample if provided
    huffman_sample = None
    if args.huffman_sample:
        with open(args.huffman_sample, "rb") as f:
            huffman_sample = f.read()

    # Generate secret
    secret = generate_secret(
        k=args.k,
        knock=knock,
        preamble_tokens=args.preamble,
        suffix_tokens=args.suffix,
        temperature=args.temperature,
        entropy_threshold=args.entropy_threshold,
        huffman_sample=huffman_sample,
        notes=args.notes or "",
    )

    # Get password
    password = get_password(args, confirm=True)

    # Save
    save_secret(secret, password, args.output)

    print(f"Secret saved to: {args.output}", file=sys.stderr)
    print(f"  K: {secret['k']} ({int(math.log2(secret['k']))} bits/token)", file=sys.stderr)
    print(f"  Knock: {secret['knock']}", file=sys.stderr)


def cmd_encode(args):
    """Handle encode command."""
    # Load secret
    password = get_password(args)
    try:
        secret = load_secret(args.secret, password)
    except ValueError as e:
        print(f"Failed to load secret: {e}", file=sys.stderr)
        sys.exit(1)

    # Read input
    if args.input:
        with open(args.input, "rb") as f:
            message = f.read()
    else:
        message = sys.stdin.buffer.read()

    # Create client
    client = create_client(args)

    try:
        # Encode
        cover_text = encode_message(
            message=message,
            secret=secret,
            client=client,
            prompt=args.prompt,
            compress=not args.no_compress,
            verbose=args.verbose,
        )

        # Output
        if args.output:
            with open(args.output, "w") as f:
                f.write(cover_text)
        else:
            print(cover_text)

    finally:
        if hasattr(client, "close"):
            client.close()


def cmd_decode(args):
    """Handle decode command."""
    # Load secret
    password = get_password(args)
    try:
        secret = load_secret(args.secret, password)
    except ValueError as e:
        print(f"Failed to load secret: {e}", file=sys.stderr)
        sys.exit(1)

    # Read input
    if args.input:
        with open(args.input) as f:
            cover_text = f.read()
    else:
        cover_text = sys.stdin.read()

    # Create client
    client = create_client(args)

    try:
        # Decode
        message = decode_message(
            cover_text=cover_text,
            secret=secret,
            client=client,
            prompt=args.prompt,
            verbose=args.verbose,
        )

        # Output
        if args.output:
            with open(args.output, "wb") as f:
                f.write(message)
        else:
            sys.stdout.buffer.write(message)

    finally:
        if hasattr(client, "close"):
            client.close()


def cmd_show_secret(args):
    """Handle show-secret command."""
    password = get_password(args)
    try:
        secret = load_secret(args.secret, password)
    except ValueError as e:
        print(f"Failed to load secret: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Version: {secret['version']}")
    print(f"K: {secret['k']} ({int(math.log2(secret['k']))} bits/token)")
    print(f"Knock: {secret['knock']}")
    print(f"Payload key: [present, {len(secret.get('payload_key', b''))} bytes]")
    print(f"Preamble tokens: {secret.get('preamble_tokens', 4)}")
    print(f"Suffix tokens: {secret.get('suffix_tokens', 2)}")
    print(f"Temperature: {secret.get('temperature', 0.8)}")
    print(f"Entropy threshold: {secret.get('entropy_threshold', 0.0)}")

    huffman_freq = secret.get("huffman_freq", {})
    print(f"Huffman frequencies: {len(huffman_freq)} entries")

    if secret.get("notes"):
        print(f"Notes: {secret['notes']}")


def main():
    parser = argparse.ArgumentParser(
        description="SlopCrypt - Encrypted Secret Wrapper for LLM Steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate secret (auto-generates random knock):
    python -m slopcrypt.secret generate-secret -o my.secret --k 16

  Generate with explicit knock:
    python -m slopcrypt.secret generate-secret -o my.secret --knock 4,7,2,9,14,1 --k 16

  Build Huffman table from sample:
    python -m slopcrypt.secret generate-secret -o my.secret --huffman-sample corpus.txt

  Encode message (prompt specified at encode time):
    echo "Secret" | python -m slopcrypt.secret encode --secret my.secret --mock --prompt "Dear diary,"

  Decode message (same prompt required for correct decoding):
    python -m slopcrypt.secret decode --secret my.secret --mock -i cover.txt --prompt "Dear diary,"

  Show secret parameters:
    python -m slopcrypt.secret show-secret --secret my.secret
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-secret
    gen_parser = subparsers.add_parser("generate-secret", help="Generate new secret")
    gen_parser.add_argument("-o", "--output", required=True, help="Output secret file")
    gen_parser.add_argument("--k", type=int, default=16, help="K value (default: 16)")
    gen_parser.add_argument(
        "--knock", help="Comma-separated knock sequence (auto-generated if not specified)"
    )
    gen_parser.add_argument(
        "--preamble", type=int, default=4, help="Preamble tokens (default: 4)"
    )
    gen_parser.add_argument("--suffix", type=int, default=2, help="Suffix tokens (default: 2)")
    gen_parser.add_argument(
        "--temperature", type=float, default=0.8, help="Temperature (default: 0.8)"
    )
    gen_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=0.0,
        help="Skip encoding if top token prob > threshold (0.0 = disabled, try 0.9 for more natural text)",
    )
    gen_parser.add_argument("--huffman-sample", help="Sample file for Huffman frequencies")
    gen_parser.add_argument("--notes", help="Optional notes/metadata")
    gen_parser.add_argument("--password", help="Password (prompted if not provided)")

    # encode
    enc_parser = subparsers.add_parser("encode", help="Encode message")
    enc_parser.add_argument("--secret", required=True, help="Secret file")
    enc_parser.add_argument("-i", "--input", help="Input file (default: stdin)")
    enc_parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    enc_parser.add_argument("--prompt", help="Prompt for cover text (default: traveler story)")
    enc_parser.add_argument(
        "--no-compress", action="store_true", help="Disable Huffman compression"
    )
    enc_parser.add_argument("--password", help="Password (prompted if not provided)")
    enc_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    # Model selection
    enc_parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to GGUF model")
    enc_parser.add_argument("--lmstudio", action="store_true", help="Use LM Studio API")
    enc_parser.add_argument("--host", default="http://192.168.1.12:1234/v1", help="LM Studio URL")
    enc_parser.add_argument("--model", help="Model name for LM Studio")
    enc_parser.add_argument("--mock", action="store_true", help="Use mock client (testing)")
    enc_parser.add_argument("--mlx", action="store_true", help="Use MLX (Apple Silicon)")
    enc_parser.add_argument(
        "--mlx-model", help="MLX model name (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)"
    )

    # decode
    dec_parser = subparsers.add_parser("decode", help="Decode message")
    dec_parser.add_argument("--secret", required=True, help="Secret file")
    dec_parser.add_argument("-i", "--input", help="Input file (default: stdin)")
    dec_parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    dec_parser.add_argument("--prompt", help="Prompt used during encoding (for context alignment)")
    dec_parser.add_argument("--password", help="Password (prompted if not provided)")
    dec_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    # Model selection
    dec_parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to GGUF model")
    dec_parser.add_argument("--lmstudio", action="store_true", help="Use LM Studio API")
    dec_parser.add_argument("--host", default="http://192.168.1.12:1234/v1", help="LM Studio URL")
    dec_parser.add_argument("--model", help="Model name for LM Studio")
    dec_parser.add_argument("--mock", action="store_true", help="Use mock client (testing)")
    dec_parser.add_argument("--mlx", action="store_true", help="Use MLX (Apple Silicon)")
    dec_parser.add_argument(
        "--mlx-model", help="MLX model name (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)"
    )

    # show-secret
    show_parser = subparsers.add_parser("show-secret", help="Show secret parameters")
    show_parser.add_argument("--secret", required=True, help="Secret file")
    show_parser.add_argument("--password", help="Password (prompted if not provided)")

    args = parser.parse_args()

    # Validate K is power of 2 for generate-secret
    if args.command == "generate-secret":
        if args.k < 2 or (args.k & (args.k - 1)) != 0:
            parser.error(f"K must be a power of 2 >= 2, got {args.k}")

    # Dispatch
    if args.command == "generate-secret":
        cmd_generate_secret(args)
    elif args.command == "encode":
        cmd_encode(args)
    elif args.command == "decode":
        cmd_decode(args)
    elif args.command == "show-secret":
        cmd_show_secret(args)


if __name__ == "__main__":
    main()
