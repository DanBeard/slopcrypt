#!/usr/bin/env python3
"""
Diagnostic script to debug knock sequence encoding/decoding.
"""

import sys
import math
from lm_client import LlamaCppClient, MockLMClient
from utils import filter_prefix_tokens, find_longest_match, find_knock_sequence

def debug_encode(client, prompt, k, knock, message=b"Test"):
    """Trace through encoding process."""
    from stego_basek import encode_with_knock

    print("=" * 60)
    print("ENCODING")
    print("=" * 60)
    print(f"Prompt: {prompt!r}")
    print(f"K: {k}")
    print(f"Knock: {knock}")
    print(f"Message: {message!r}")
    print()

    # Trace preamble generation
    context = prompt
    bits_per_token = int(math.log2(k))

    print("--- Preamble tokens ---")
    preamble_indices = []
    for i in range(10):  # preamble_tokens=10
        dist = client.get_token_distribution(context)
        top_k = filter_prefix_tokens(dist, k)

        # Just take index 0 for simplicity (would be sampled in real code)
        if top_k:
            # Simulate sampling - pick a random-ish token
            import random
            idx = random.randint(0, min(len(top_k)-1, k-1))
            token = top_k[idx].token
            preamble_indices.append(idx)
            context += token
            print(f"  {i}: idx={idx} token={token!r} (top_k has {len(top_k)} tokens)")

    print(f"\nPreamble indices: {preamble_indices}")

    print("\n--- Knock sequence ---")
    knock_tokens = []
    for i, idx in enumerate(knock):
        dist = client.get_token_distribution(context)
        top_k = filter_prefix_tokens(dist, k)
        actual_idx = idx % len(top_k) if idx >= len(top_k) else idx
        if top_k and actual_idx < len(top_k):
            token = top_k[actual_idx].token
            knock_tokens.append(token)
            context += token
            print(f"  {i}: want_idx={idx} actual_idx={actual_idx} token={token!r} (top_k has {len(top_k)} tokens)")
        else:
            print(f"  {i}: want_idx={idx} - NO TOKEN AVAILABLE (top_k has {len(top_k)} tokens)")

    print(f"\nKnock tokens: {knock_tokens}")
    print(f"Full context length: {len(context)}")

    return context  # This is prompt + preamble + knock (no payload for simplicity)


def debug_decode(client, cover_text, k, knock):
    """Trace through decoding process."""
    print("\n" + "=" * 60)
    print("DECODING")
    print("=" * 60)
    print(f"Cover text length: {len(cover_text)}")
    print(f"Cover text preview: {cover_text[:100]!r}...")
    print(f"K: {k}")
    print(f"Looking for knock: {knock}")
    print()

    context = ""
    remaining = cover_text
    token_indices = []
    tokens_found = []
    skipped_chars = 0

    print("--- Token matching ---")
    token_num = 0

    while remaining and token_num < 50:  # Limit output
        dist = client.get_token_distribution(context)
        if not dist:
            print(f"  No distribution for context len={len(context)}")
            break

        top_k = filter_prefix_tokens(dist, k)
        matched, matched_index = find_longest_match(remaining, top_k)

        if matched is None:
            # Skip character
            skipped_char = remaining[0]
            context += skipped_char
            remaining = remaining[1:]
            skipped_chars += 1
            # Only print first few skips
            if skipped_chars <= 10:
                print(f"  SKIP: {skipped_char!r} (context now {len(context)} chars)")
            elif skipped_chars == 11:
                print(f"  ... (more skips)")
        else:
            token_indices.append(matched_index)
            tokens_found.append(matched.token)
            context += matched.token
            remaining = remaining[len(matched.token):]
            print(f"  TOKEN {token_num}: idx={matched_index} token={matched.token!r} (top_k has {len(top_k)} tokens)")
            token_num += 1

    print(f"\nTotal skipped characters: {skipped_chars}")
    print(f"Total tokens matched: {len(token_indices)}")
    print(f"Token indices: {token_indices[:30]}{'...' if len(token_indices) > 30 else ''}")

    # Find knock
    knock_pos = find_knock_sequence(token_indices, knock)
    print(f"\nKnock sequence {knock} found at position: {knock_pos}")

    if knock_pos >= 0:
        print(f"Tokens around knock:")
        start = max(0, knock_pos - 2)
        end = min(len(token_indices), knock_pos + len(knock) + 2)
        for i in range(start, end):
            marker = " <-- KNOCK" if knock_pos <= i < knock_pos + len(knock) else ""
            print(f"  [{i}] idx={token_indices[i]} token={tokens_found[i]!r}{marker}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", help="Path to GGUF model")
    parser.add_argument("--mock", action="store_true", help="Use mock client")
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--knock", default="1,2,3,0,1,2", help="Comma-separated knock")
    parser.add_argument("--prompt", default="Once upon a time")
    args = parser.parse_args()

    knock = [int(x) for x in args.knock.split(",")]

    if args.mock:
        client = MockLMClient(vocab_size=32)
    elif args.model_path:
        client = LlamaCppClient(model_path=args.model_path, top_k=64)
    else:
        print("Specify --mock or --model-path")
        sys.exit(1)

    try:
        # Encode
        cover_text = debug_encode(client, args.prompt, args.k, knock)

        # Decode
        debug_decode(client, cover_text, args.k, knock)

    finally:
        if hasattr(client, 'close'):
            client.close()


if __name__ == "__main__":
    main()
