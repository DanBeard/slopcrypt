/**
 * Fixed distribution LM client for cross-language compatibility testing.
 *
 * This client returns identical hard-coded distributions in both Python and TypeScript,
 * enabling deterministic cross-language testing of the steganography system.
 */

import type { LMClient, TokenProb } from './types.ts';

/**
 * LM client that returns a fixed, deterministic distribution.
 *
 * Used for cross-language compatibility testing where Python and TypeScript
 * implementations must produce identical results. Unlike mock clients which
 * use context-dependent hashing (which differs between languages), this
 * client always returns the same hard-coded distribution.
 */
export class FixedDistributionClient implements LMClient {
  /**
   * 32 tokens with probabilities summing to 1.0
   * These are sorted by probability descending, then by token string.
   * MUST be identical to Python's FixedDistributionClient.FIXED_VOCAB
   */
  static readonly FIXED_VOCAB: readonly [string, number][] = [
    [' the', 0.12],
    [' a', 0.10],
    [' to', 0.08],
    [' and', 0.07],
    [' of', 0.06],
    [' in', 0.05],
    [' is', 0.045],
    [' that', 0.04],
    [' it', 0.035],
    [' for', 0.03],
    [' was', 0.028],
    [' on', 0.026],
    [' with', 0.024],
    [' as', 0.022],
    [' be', 0.02],
    [' at', 0.018],
    [' by', 0.016],
    [' this', 0.015],
    [' from', 0.014],
    [' or', 0.013],
    [' an', 0.012],
    [' but', 0.011],
    [' not', 0.010],
    [' are', 0.009],
    [' have', 0.008],
    [' were', 0.007],
    [' been', 0.006],
    [' has', 0.005],
    [' their', 0.004],
    [' which', 0.003],
    [' when', 0.002],
    [' there', 0.001],
  ] as const;

  private vocabSize: number;

  /**
   * Initialize fixed distribution client.
   * @param vocabSize Number of tokens to return (max 32)
   */
  constructor(vocabSize: number = 32) {
    this.vocabSize = Math.min(vocabSize, FixedDistributionClient.FIXED_VOCAB.length);
  }

  /**
   * Return fixed distribution regardless of context.
   *
   * The distribution is always the same, ensuring identical behavior
   * across Python and TypeScript implementations.
   */
  async getTokenDistribution(_context: string): Promise<TokenProb[]> {
    return FixedDistributionClient.FIXED_VOCAB.slice(0, this.vocabSize).map(
      ([token, prob]) => ({ token, prob })
    );
  }
}
