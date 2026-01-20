#!/usr/bin/env python3
"""
Test if the model returns consistent distributions for the same context.
"""

import sys
from lm_client import LlamaCppClient
from utils import filter_prefix_tokens


def test_consistency(model_path, context, k=16, num_calls=5):
    """Call the model multiple times with the same context and compare results."""

    print(f"Testing model consistency with context: {context!r}")
    print(f"K={k}, making {num_calls} calls\n")

    client = LlamaCppClient(model_path=model_path, top_k=64)

    results = []
    for i in range(num_calls):
        try:
            dist = client.get_token_distribution(context)
            if not dist:
                print(f"Call {i}: EMPTY DISTRIBUTION")
                results.append(None)
                continue

            top_k = filter_prefix_tokens(dist, k)

            # Record top tokens and their indices
            top_tokens = [(j, t.token, t.prob) for j, t in enumerate(top_k[:10])]
            results.append(top_tokens)

            print(f"Call {i}: {len(dist)} raw tokens, {len(top_k)} after filtering")
            for idx, token, prob in top_tokens[:5]:
                print(f"  [{idx}] {token!r:15s} prob={prob:.6f}")

        except Exception as e:
            print(f"Call {i}: EXCEPTION - {type(e).__name__}: {e}")
            results.append(None)

        print()

    # Check consistency
    print("=" * 50)
    print("CONSISTENCY CHECK")
    print("=" * 50)

    valid_results = [r for r in results if r is not None]
    if not valid_results:
        print("No valid results!")
        return

    # Compare all results to the first one
    reference = valid_results[0]
    all_match = True

    for i, result in enumerate(valid_results[1:], 1):
        ref_tokens = [t[1] for t in reference]
        cur_tokens = [t[1] for t in result]

        if ref_tokens != cur_tokens:
            print(f"MISMATCH: Call {i} differs from call 0")
            print(f"  Ref: {ref_tokens[:5]}")
            print(f"  Cur: {cur_tokens[:5]}")
            all_match = False

    if all_match:
        print("All calls returned CONSISTENT results!")
    else:
        print("WARNING: Results are INCONSISTENT between calls!")

    client.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--context", default="Once upon a time")
    parser.add_argument("--k", type=int, default=16)
    args = parser.parse_args()

    test_consistency(args.model_path, args.context, args.k)
