#!/usr/bin/env python3
"""
SlopCrypt - Base-K LLM Steganography

Simple approach: map each log2(K) bits to one of the top-K tokens.
Much simpler than arithmetic coding, very robust.

Usage:
    python -m slopcrypt.encode encode -i secret.bin -o cover.txt --mock
    python -m slopcrypt.encode decode -i cover.txt -o recovered.bin --mock
"""

import argparse
import math
import random
import sys

from slopcrypt.lm_client import DEFAULT_MODEL_PATH, LlamaCppClient, MockLMClient
from slopcrypt.utils import (
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

DEFAULT_PROMPT = """Write a short story about a traveler:

The weary traveler had been walking for"""
DEFAULT_K = 16  # 4 bits per token


def sample_from_distribution(top_k: list, temperature: float = 1.0) -> tuple[int, str]:
    """
    Sample a token from distribution using temperature-scaled probabilities.

    Args:
        top_k: List of TokenProb objects
        temperature: Sampling temperature (higher = more random)

    Returns:
        Tuple of (index, token_string)
    """
    if not top_k:
        return 0, ""

    if temperature <= 0 or len(top_k) == 1:
        # Greedy
        return 0, top_k[0].token

    # Apply temperature scaling to probabilities
    probs = [t.prob for t in top_k]

    # Temperature scaling (in log space for numerical stability)
    scaled = [p ** (1.0 / temperature) for p in probs]
    total = sum(scaled)

    if total <= 0:
        return 0, top_k[0].token

    normalized = [p / total for p in scaled]

    # Sample
    r = random.random()
    cumulative = 0.0
    for i, p in enumerate(normalized):
        cumulative += p
        if r < cumulative:
            return i, top_k[i].token

    return len(top_k) - 1, top_k[-1].token


def encode(
    data: bytes,
    client,
    prompt: str,
    k: int = DEFAULT_K,
    verbose: bool = False,
) -> str:
    """
    Encode binary data using Base-K steganography.

    Each token encodes log2(K) bits by selecting from top-K tokens.
    First 4 bytes encode the payload length.
    """
    bits_per_token = int(math.log2(k))

    # Prepend 4-byte length header
    full_data = len(data).to_bytes(4, "big") + data
    bit_stream = bytes_to_bits(full_data)

    context = prompt
    tokens = []
    bit_idx = 0

    while bit_idx < len(bit_stream):
        # Get next chunk of bits
        chunk = bit_stream[bit_idx : bit_idx + bits_per_token]
        # Pad if needed (last chunk)
        while len(chunk) < bits_per_token:
            chunk.append(0)

        index = bits_to_int(chunk)

        # Get distribution and select token by index
        dist = client.get_token_distribution(context)
        if not dist:
            if verbose:
                print(f"Warning: Empty distribution at token {len(tokens)}", file=sys.stderr)
            break

        top_k = filter_prefix_tokens(dist, k)

        if not top_k:
            if verbose:
                print(f"Warning: No valid tokens after filtering at {len(tokens)}", file=sys.stderr)
            break

        # If fewer than K tokens, wrap index
        if index >= len(top_k):
            index = index % len(top_k)

        token = top_k[index].token
        tokens.append(token)
        context += token
        bit_idx += bits_per_token

        if verbose and len(tokens) % 50 == 0:
            print(
                f"Encoded {len(tokens)} tokens ({bit_idx}/{len(bit_stream)} bits)...",
                file=sys.stderr,
            )

    if verbose:
        print(
            f"Encoding complete: {len(tokens)} tokens, {bits_per_token} bits/token", file=sys.stderr
        )

    return "".join(tokens)


def encode_with_knock(
    data: bytes,
    client,
    prompt: str,
    k: int,
    knock: list[int],
    preamble_tokens: int = 10,
    suffix_tokens: int = 10,
    temperature: float = 0.8,
    verbose: bool = False,
) -> str:
    """
    Encode binary data with knock sequence for natural-looking cover text.

    1. Generate preamble_tokens naturally (greedy selection)
    2. Encode knock sequence
    3. Encode length + payload
    4. Generate suffix_tokens naturally
    """
    bits_per_token = int(math.log2(k))

    # Prepend 4-byte length header
    full_data = len(data).to_bytes(4, "big") + data
    bit_stream = bytes_to_bits(full_data)

    # Check if knock sequence would appear in payload
    if check_knock_in_data(bit_stream, knock, bits_per_token):
        raise ValueError(
            "Knock sequence would appear in encoded payload, use different knock sequence"
        )

    context = prompt
    tokens = []

    # Phase 1: Generate preamble naturally (sampling)
    if verbose:
        print(
            f"Generating {preamble_tokens} preamble tokens (temp={temperature})...", file=sys.stderr
        )

    preamble_indices = []
    for _ in range(preamble_tokens):
        dist = client.get_token_distribution(context)
        if not dist:
            break
        top_k = filter_prefix_tokens(dist, k)
        if not top_k:
            break
        # Sample from distribution for natural text
        idx, token = sample_from_distribution(top_k, temperature)
        tokens.append(token)
        preamble_indices.append(idx)
        context += token

    # Check if knock sequence appears in preamble
    if find_knock_sequence(preamble_indices, knock) != -1:
        raise ValueError("Knock sequence found in preamble, use different knock sequence or prompt")

    # Phase 2: Encode knock sequence
    if verbose:
        print(f"Encoding knock sequence: {knock}", file=sys.stderr)

    for idx in knock:
        dist = client.get_token_distribution(context)
        if not dist:
            raise RuntimeError("Empty distribution while encoding knock sequence")
        top_k = filter_prefix_tokens(dist, k)
        if not top_k:
            raise RuntimeError("No valid tokens while encoding knock sequence")
        # Select token at knock index (wrap if needed)
        actual_idx = idx % len(top_k) if idx >= len(top_k) else idx
        token = top_k[actual_idx].token
        tokens.append(token)
        context += token

    # Phase 3: Encode length + payload
    if verbose:
        print(f"Encoding {len(data)} bytes payload...", file=sys.stderr)

    bit_idx = 0
    while bit_idx < len(bit_stream):
        chunk = bit_stream[bit_idx : bit_idx + bits_per_token]
        while len(chunk) < bits_per_token:
            chunk.append(0)

        index = bits_to_int(chunk)

        dist = client.get_token_distribution(context)
        if not dist:
            if verbose:
                print(f"Warning: Empty distribution at token {len(tokens)}", file=sys.stderr)
            break

        top_k = filter_prefix_tokens(dist, k)
        if not top_k:
            if verbose:
                print(f"Warning: No valid tokens at {len(tokens)}", file=sys.stderr)
            break

        if index >= len(top_k):
            index = index % len(top_k)

        token = top_k[index].token
        tokens.append(token)
        context += token
        bit_idx += bits_per_token

    # Phase 4: Generate suffix naturally (sampling)
    if verbose:
        print(f"Generating {suffix_tokens} suffix tokens (temp={temperature})...", file=sys.stderr)

    for _ in range(suffix_tokens):
        dist = client.get_token_distribution(context)
        if not dist:
            break
        top_k = filter_prefix_tokens(dist, k)
        if not top_k:
            break
        # Sample from distribution for natural text
        _, token = sample_from_distribution(top_k, temperature)
        tokens.append(token)
        context += token

    if verbose:
        print(
            f"Encoding complete: {len(tokens)} tokens ({preamble_tokens} preamble + "
            f"{len(knock)} knock + payload + {suffix_tokens} suffix)",
            file=sys.stderr,
        )

    # Return prompt + generated tokens as complete cover text
    return prompt + "".join(tokens)


def decode(
    cover_text: str,
    client,
    prompt: str,
    k: int = DEFAULT_K,
    verbose: bool = False,
) -> bytes:
    """
    Decode binary data from Base-K steganography.

    Finds each token's index in top-K to recover the bits.
    """
    bits_per_token = int(math.log2(k))

    context = prompt
    remaining = cover_text
    bits = []
    token_count = 0

    # First pass: recover all bits
    while remaining:
        dist = client.get_token_distribution(context)
        if not dist:
            break

        top_k = filter_prefix_tokens(dist, k)

        # Find which token from top-K matches the start of remaining text
        matched, matched_index = find_longest_match(remaining, top_k)

        if matched is None:
            # Token not in top-K, skip character
            if verbose:
                print(f"Warning: No match in top-{k} for '{remaining[:20]}...'", file=sys.stderr)
            context += remaining[0]
            remaining = remaining[1:]
            continue

        # Convert index to bits
        token_bits = int_to_bits(matched_index, bits_per_token)
        bits.extend(token_bits)

        context += matched.token
        remaining = remaining[len(matched.token) :]
        token_count += 1

        if verbose and token_count % 50 == 0:
            print(f"Decoded {token_count} tokens...", file=sys.stderr)

        # Check if we have enough bits to read the length header
        if len(bits) >= 32 and token_count * bits_per_token >= 32:
            # Check if we've decoded enough
            length_bits = bits[:32]
            payload_len = bits_to_int(length_bits)
            total_bits_needed = 32 + payload_len * 8

            if len(bits) >= total_bits_needed:
                if verbose:
                    print(f"Got all {total_bits_needed} bits, stopping", file=sys.stderr)
                break

    if verbose:
        print(f"Decoding complete: {token_count} tokens, {len(bits)} bits", file=sys.stderr)

    # Convert bits to bytes
    all_bytes = bits_to_bytes(bits)

    if len(all_bytes) < 4:
        return b""

    # Extract length and payload
    payload_len = int.from_bytes(all_bytes[:4], "big")

    if payload_len > len(all_bytes) - 4:
        if verbose:
            print(
                f"Warning: payload_len={payload_len} but only {len(all_bytes) - 4} bytes available",
                file=sys.stderr,
            )
        payload_len = len(all_bytes) - 4

    return all_bytes[4 : 4 + payload_len]


def decode_with_knock(
    cover_text: str,
    client,
    k: int,
    knock: list[int],
    prompt: str = "",
    verbose: bool = False,
) -> bytes:
    """
    Decode binary data from cover text with knock sequence.

    1. Walk through cover text, building context as we go
    2. Track token indices at each position
    3. Scan for knock sequence
    4. Once found, decode payload starting after knock
    5. Stop at length header boundary

    Args:
        cover_text: Full cover text (may include prompt)
        client: LLM client
        k: Number of top tokens to consider
        knock: Knock sequence to find
        prompt: Optional prompt to strip from cover text (for correct context)
        verbose: Print debug info
    """
    bits_per_token = int(math.log2(k))

    # If prompt provided and cover_text starts with it, strip prompt and use as context
    if prompt and cover_text.startswith(prompt):
        context = prompt
        remaining = cover_text[len(prompt) :]
        if verbose:
            print(
                f"Stripped prompt ({len(prompt)} chars), starting with generated tokens",
                file=sys.stderr,
            )
    else:
        context = ""
        remaining = cover_text
    token_indices = []
    token_positions = []  # Track where each token ends in cover_text
    token_count = 0
    consumed = 0

    # Phase 1: Scan all tokens and collect indices
    if verbose:
        print(f"Scanning for knock sequence {knock}...", file=sys.stderr)

    while remaining:
        dist = client.get_token_distribution(context)
        if not dist:
            # Empty distribution (e.g., model error for empty context) - skip character
            context += remaining[0]
            remaining = remaining[1:]
            consumed += 1
            continue

        top_k = filter_prefix_tokens(dist, k)

        if not top_k:
            # No tokens after filtering - skip character
            context += remaining[0]
            remaining = remaining[1:]
            consumed += 1
            continue

        matched, matched_index = find_longest_match(remaining, top_k)

        if matched is None:
            # Token not in top-K, skip character
            context += remaining[0]
            remaining = remaining[1:]
            consumed += 1
            continue

        token_indices.append(matched_index)
        consumed += len(matched.token)
        token_positions.append(consumed)
        context += matched.token
        remaining = remaining[len(matched.token) :]
        token_count += 1

    # Phase 2: Find knock sequence
    knock_pos = find_knock_sequence(token_indices, knock)

    if knock_pos == -1:
        raise ValueError("Knock sequence not found in cover text")

    if verbose:
        print(f"Found knock at token position {knock_pos}", file=sys.stderr)

    # Phase 3: Extract payload indices (after knock)
    payload_start = knock_pos + len(knock)
    payload_indices = token_indices[payload_start:]

    if verbose:
        print(f"Decoding from {len(payload_indices)} payload tokens...", file=sys.stderr)

    # Phase 4: Convert indices to bits
    bits = []
    for idx in payload_indices:
        token_bits = int_to_bits(idx, bits_per_token)
        bits.extend(token_bits)

        # Check if we have enough bits to read the length header
        if len(bits) >= 32:
            length_bits = bits[:32]
            payload_len = bits_to_int(length_bits)
            total_bits_needed = 32 + payload_len * 8

            if len(bits) >= total_bits_needed:
                if verbose:
                    print(f"Got all {total_bits_needed} bits, stopping", file=sys.stderr)
                break

    if verbose:
        print(
            f"Decoding complete: {len(bits)} bits from {len(payload_indices)} tokens",
            file=sys.stderr,
        )

    # Convert bits to bytes
    all_bytes = bits_to_bytes(bits)

    if len(all_bytes) < 4:
        return b""

    # Extract length and payload
    payload_len = int.from_bytes(all_bytes[:4], "big")

    if payload_len > len(all_bytes) - 4:
        if verbose:
            print(
                f"Warning: payload_len={payload_len} but only {len(all_bytes) - 4} bytes available",
                file=sys.stderr,
            )
        payload_len = len(all_bytes) - 4

    return all_bytes[4 : 4 + payload_len]


def main():
    parser = argparse.ArgumentParser(
        description="SlopCrypt - Base-K LLM Steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Encode with mock client (for testing):
    python -m slopcrypt.encode encode -i secret.txt -o cover.txt --mock

  Decode:
    python -m slopcrypt.encode decode -i cover.txt -o recovered.txt --mock

  Use real model:
    python -m slopcrypt.encode encode -i secret.txt -o cover.txt --model-path model.gguf

  Adjust K (bits per token = log2(K)):
    python -m slopcrypt.encode encode -i secret.txt -k 32  # 5 bits/token
    python -m slopcrypt.encode encode -i secret.txt -k 8   # 3 bits/token

  Token knock mode (natural-looking cover text):
    echo "Secret" | python -m slopcrypt.encode encode --mock --knock 4,7,2,9 --preamble 20 --suffix 15
    python -m slopcrypt.encode decode --mock --knock 4,7,2,9 -i cover.txt
        """,
    )

    parser.add_argument("mode", choices=["encode", "decode"])
    parser.add_argument("-i", "--input", help="Input file (default: stdin)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    parser.add_argument(
        "-k",
        type=int,
        default=DEFAULT_K,
        help=f"Number of tokens to choose from (default: {DEFAULT_K}, must be power of 2)",
    )
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help="Initial prompt")

    # Model selection
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to GGUF model")
    parser.add_argument("--mock", action="store_true", help="Use mock client (testing)")
    parser.add_argument("--mlx", action="store_true", help="Use MLX (Apple Silicon)")
    parser.add_argument(
        "--mlx-model", help="MLX model name (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)"
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Token knock options
    parser.add_argument("--knock", help="Comma-separated knock sequence (e.g., 4,7,2,9)")
    parser.add_argument(
        "--preamble",
        type=int,
        default=10,
        help="Natural tokens to generate before knock (default: 10)",
    )
    parser.add_argument(
        "--suffix",
        type=int,
        default=10,
        help="Natural tokens to generate after payload (default: 10)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.8,
        help="Sampling temperature for preamble/suffix (default: 0.8)",
    )

    args = parser.parse_args()

    # Validate K is power of 2
    if args.k & (args.k - 1) != 0 or args.k < 2:
        parser.error(f"K must be a power of 2 (got {args.k})")

    # Parse knock sequence if provided
    knock = None
    if args.knock:
        try:
            knock = parse_knock_sequence(args.knock, args.k)
        except ValueError as e:
            parser.error(str(e))

    # Read input
    if args.input:
        mode = "rb" if args.mode == "encode" else "r"
        with open(args.input, mode) as f:
            input_data = f.read()
    else:
        if args.mode == "encode":
            input_data = sys.stdin.buffer.read()
        else:
            input_data = sys.stdin.read()

    # Create client
    if args.mock:
        client = MockLMClient(vocab_size=max(32, args.k))
    elif args.mlx:
        if not args.mlx_model:
            parser.error("--mlx-model required (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)")
        from slopcrypt.lm_client import MLXClient

        client = MLXClient(model_name=args.mlx_model, top_k=max(40, args.k))
    else:
        if not args.model_path:
            parser.error("Model path required. Use --model-path or --mock")
        client = LlamaCppClient(model_path=args.model_path, top_k=max(32, args.k))

    try:
        if args.mode == "encode":
            if args.verbose:
                bits_per_token = int(math.log2(args.k))
                total_bits = (len(input_data) + 4) * 8
                est_tokens = (total_bits + bits_per_token - 1) // bits_per_token
                print(
                    f"Encoding {len(input_data)} bytes (~{est_tokens} tokens at {bits_per_token} bits/token)",
                    file=sys.stderr,
                )

            if knock:
                result = encode_with_knock(
                    input_data,
                    client,
                    args.prompt,
                    k=args.k,
                    knock=knock,
                    preamble_tokens=args.preamble,
                    suffix_tokens=args.suffix,
                    temperature=args.temperature,
                    verbose=args.verbose,
                )
            else:
                result = encode(input_data, client, args.prompt, k=args.k, verbose=args.verbose)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(result)
            else:
                print(result)

        else:  # decode
            if args.verbose:
                print(f"Decoding {len(input_data)} characters...", file=sys.stderr)

            if knock:
                result = decode_with_knock(
                    input_data, client, k=args.k, knock=knock, verbose=args.verbose
                )
            else:
                result = decode(input_data, client, args.prompt, k=args.k, verbose=args.verbose)

            if args.output:
                with open(args.output, "wb") as f:
                    f.write(result)
            else:
                sys.stdout.buffer.write(result)

    finally:
        if hasattr(client, "close"):
            client.close()


if __name__ == "__main__":
    main()
