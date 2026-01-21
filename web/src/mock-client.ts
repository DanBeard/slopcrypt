/**
 * Mock LM client for testing without real models.
 * Port of lm_client.py lines 291-385 (MockLMClient).
 */

import type { LMClient, TokenProb } from './types.ts';

/**
 * Mock LM client that generates deterministic distributions based on context hash.
 */
export class MockLMClient implements LMClient {
  private seed: number;
  private vocab: string[];

  constructor(vocabSize: number = 32, seed: number = 42) {
    this.seed = seed;

    // Simple vocabulary of common words/tokens
    this.vocab = [
      ' the',
      ' a',
      ' an',
      ' is',
      ' was',
      ' are',
      ' were',
      ' be',
      ' been',
      ' being',
      ' have',
      ' has',
      ' had',
      ' do',
      ' does',
      ' did',
      ' will',
      ' would',
      ' could',
      ' should',
      ' may',
      ' might',
      ' must',
      ' shall',
      ' can',
      ' need',
      ' dare',
      ' ought',
      ' used',
      ' to',
      ' of',
      ' in',
    ].slice(0, vocabSize);
  }

  /**
   * Generate deterministic hash from context.
   */
  private hashContext(context: string): number {
    let h = this.seed;
    for (const c of context) {
      h = ((h * 31 + c.charCodeAt(0)) & 0xffffffff) >>> 0;
    }
    return h;
  }

  /**
   * Generate deterministic distribution based on context.
   */
  async getTokenDistribution(context: string): Promise<TokenProb[]> {
    const h = this.hashContext(context);

    // Generate probabilities using the hash
    const probs: number[] = [];

    for (let i = 0; i < this.vocab.length; i++) {
      // Use hash to generate pseudo-random probability
      const tokenHash = (((h * (i + 1)) ^ (h >>> 16)) & 0xffffffff) >>> 0;
      // Zipf-like distribution: earlier tokens more likely
      const baseProb = 1.0 / (i + 1);
      const noise = (tokenHash % 1000) / 10000.0; // Small noise
      const prob = baseProb + noise;
      probs.push(prob);
    }

    // Normalize
    const total = probs.reduce((a, b) => a + b, 0);
    const result: TokenProb[] = this.vocab.map((token, i) => ({
      token,
      prob: probs[i] / total,
    }));

    // Sort by probability descending
    result.sort((a, b) => b.prob - a.prob);

    return result;
  }
}
