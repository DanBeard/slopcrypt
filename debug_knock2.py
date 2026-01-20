#!/usr/bin/env python3
"""
Diagnostic script to debug knock sequence with real encoding/decoding.
"""

import sys
import math
from lm_client import LlamaCppClient, MockLMClient
from stego_basek import encode_with_knock, decode_with_knock
from utils import filter_prefix_tokens, find_longest_match, find_knock_sequence


def trace_decode(client, cover_text, k, knock):
    """Detailed trace of decoding process."""
    print("\n" + "=" * 60)
    print("DETAILED DECODE TRACE")
    print("=" * 60)
    print(f"Cover text ({len(cover_text)} chars):")
    print(f"  {cover_text[:200]}{'...' if len(cover_text) > 200 else ''}")
    print(f"\nLooking for knock: {knock}")
    print()

    context = ""
    remaining = cover_text
    token_indices = []
    tokens_matched = []
    skip_count = 0

    while remaining:
        dist = client.get_token_distribution(context)
        if not dist:
            print(f"[!] No distribution at context len={len(context)}")
            break

        top_k = filter_prefix_tokens(dist, k)
        matched, matched_index = find_longest_match(remaining, top_k)

        if matched is None:
            context += remaining[0]
            remaining = remaining[1:]
            skip_count += 1
        else:
            if skip_count > 0:
                print(f"[SKIPPED {skip_count} chars, context now: ...{context[-30:]!r}]")
                skip_count = 0

            token_indices.append(matched_index)
            tokens_matched.append(matched.token)

            # Show context snippet before match
            ctx_preview = context[-20:] if len(context) > 20 else context
            print(f"[{len(token_indices)-1:3d}] idx={matched_index:2d} token={matched.token!r:12s} "
                  f"ctx=...{ctx_preview!r} top_k_size={len(top_k)}")

            context += matched.token
            remaining = remaining[len(matched.token):]

        # Stop after enough tokens
        if len(token_indices) >= 40:
            print(f"... (stopped after 40 tokens)")
            break

    if skip_count > 0:
        print(f"[SKIPPED final {skip_count} chars]")

    print(f"\n--- Summary ---")
    print(f"Total tokens matched: {len(token_indices)}")
    print(f"Indices: {token_indices}")

    # Find knock
    knock_pos = find_knock_sequence(token_indices, knock)
    if knock_pos >= 0:
        print(f"\nKnock found at position {knock_pos}!")
        print(f"Surrounding tokens:")
        for i in range(max(0, knock_pos-2), min(len(token_indices), knock_pos+len(knock)+2)):
            marker = " <-- KNOCK" if knock_pos <= i < knock_pos + len(knock) else ""
            print(f"  [{i}] idx={token_indices[i]} token={tokens_matched[i]!r}{marker}")
    else:
        print(f"\nKnock NOT FOUND!")
        print(f"Expected: {knock}")
        # Try to find partial matches
        for start in range(len(token_indices) - len(knock) + 1):
            window = token_indices[start:start + len(knock)]
            matches = sum(1 for a, b in zip(window, knock) if a == b)
            if matches >= len(knock) // 2:
                print(f"Partial match at {start}: {window} ({matches}/{len(knock)} match)")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", help="Path to GGUF model")
    parser.add_argument("--mock", action="store_true", help="Use mock client")
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--knock", default="1,2,3,0,1,2", help="Comma-separated knock")
    parser.add_argument("--prompt", default="Once upon a time")
    parser.add_argument("--preamble", type=int, default=10)
    parser.add_argument("--suffix", type=int, default=5)
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
        print("=" * 60)
        print("ENCODING")
        print("=" * 60)
        print(f"Prompt: {args.prompt!r}")
        print(f"K: {args.k}, Knock: {knock}")
        print()

        cover_text = encode_with_knock(
            data=b"Test",
            client=client,
            prompt=args.prompt,
            k=args.k,
            knock=knock,
            preamble_tokens=args.preamble,
            suffix_tokens=args.suffix,
            temperature=0.8,
            verbose=True,
        )

        print(f"\nGenerated cover text ({len(cover_text)} chars):")
        print(cover_text[:300])

        # Decode with trace
        trace_decode(client, cover_text, args.k, knock)

        # Try actual decode
        print("\n" + "=" * 60)
        print("ACTUAL DECODE")
        print("=" * 60)
        try:
            result = decode_with_knock(cover_text, client, args.k, knock, verbose=True)
            print(f"Decoded: {result!r}")
        except ValueError as e:
            print(f"DECODE FAILED: {e}")

    finally:
        if hasattr(client, 'close'):
            client.close()


if __name__ == "__main__":
    main()
