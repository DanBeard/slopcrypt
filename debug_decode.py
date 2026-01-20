#!/usr/bin/env python3
"""
Diagnostic script to debug decode issues with real LLMs.
"""

import sys
import math
from lm_client import LlamaCppClient
from utils import filter_prefix_tokens, find_longest_match, find_knock_sequence


def debug_decode(model_path, cover_text_path, k, knock):
    """Detailed trace of what's happening during decode."""

    # Read cover text
    with open(cover_text_path, 'r') as f:
        cover_text = f.read()

    print("=" * 70)
    print("DECODE DIAGNOSTIC")
    print("=" * 70)
    print(f"Cover text length: {len(cover_text)} chars")
    print(f"Cover text preview:\n{cover_text[:300]}")
    print(f"\nK: {k}")
    print(f"Looking for knock: {knock}")
    print("=" * 70)

    # Create client
    print(f"\nLoading model: {model_path}")
    client = LlamaCppClient(model_path=model_path, top_k=64, n_ctx=2048)
    print(f"Model context window: {client._n_ctx}")

    context = ""
    remaining = cover_text
    token_indices = []
    tokens_matched = []
    skip_count = 0
    errors = 0
    empty_dists = 0

    print("\n--- Walking through cover text ---\n")

    iteration = 0
    while remaining and iteration < 500:  # Limit iterations
        iteration += 1

        # Get distribution
        try:
            dist = client.get_token_distribution(context)
        except Exception as e:
            print(f"[EXCEPTION at iter {iteration}] {type(e).__name__}: {e}")
            errors += 1
            context += remaining[0]
            remaining = remaining[1:]
            skip_count += 1
            continue

        if not dist:
            empty_dists += 1
            if empty_dists <= 5:
                ctx_preview = context[-30:] if len(context) > 30 else context
                print(f"[EMPTY DIST at iter {iteration}] context ends: ...{ctx_preview!r}")
            context += remaining[0]
            remaining = remaining[1:]
            skip_count += 1
            continue

        top_k = filter_prefix_tokens(dist, k)

        if not top_k:
            if empty_dists <= 5:
                print(f"[NO TOP-K at iter {iteration}] dist had {len(dist)} tokens but none survived filtering")
            context += remaining[0]
            remaining = remaining[1:]
            skip_count += 1
            continue

        matched, matched_index = find_longest_match(remaining, top_k)

        if matched is None:
            context += remaining[0]
            remaining = remaining[1:]
            skip_count += 1
        else:
            if skip_count > 0:
                print(f"[SKIPPED {skip_count} chars]")
                skip_count = 0

            token_indices.append(matched_index)
            tokens_matched.append(matched.token)

            ctx_preview = context[-20:] if len(context) > 20 else context
            print(f"[TOKEN {len(token_indices)-1:3d}] idx={matched_index:2d} "
                  f"token={matched.token!r:15s} remaining={remaining[:20]!r}...")

            context += matched.token
            remaining = remaining[len(matched.token):]

    if skip_count > 0:
        print(f"[SKIPPED final {skip_count} chars]")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total iterations: {iteration}")
    print(f"Tokens matched: {len(token_indices)}")
    print(f"Empty distributions: {empty_dists}")
    print(f"Exceptions: {errors}")
    print(f"Remaining text: {len(remaining)} chars")

    print(f"\nAll matched indices: {token_indices}")

    # Try to find knock
    knock_pos = find_knock_sequence(token_indices, knock)
    if knock_pos >= 0:
        print(f"\n*** KNOCK FOUND at position {knock_pos}! ***")
    else:
        print(f"\n*** KNOCK NOT FOUND ***")
        print(f"Looking for: {knock}")

        # Show windows that partially match
        if len(token_indices) >= len(knock):
            print("\nPartial matches:")
            for i in range(len(token_indices) - len(knock) + 1):
                window = token_indices[i:i+len(knock)]
                matches = sum(1 for a, b in zip(window, knock) if a == b)
                if matches >= 2:
                    print(f"  Position {i}: {window} ({matches}/{len(knock)} match)")

    client.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--cover", required=True, help="Cover text file")
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--knock", required=True, help="Comma-separated knock sequence")
    args = parser.parse_args()

    knock = [int(x) for x in args.knock.split(",")]
    debug_decode(args.model_path, args.cover, args.k, knock)
