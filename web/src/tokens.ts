/**
 * Token utilities.
 * Port of utils.py lines 59-208.
 */

import type { TokenProb } from './types.ts';

/**
 * Filter out tokens that are prefixes of other tokens, return top-k.
 * This prevents ambiguity during decoding where a shorter token
 * could match when a longer one was intended.
 */
export function filterPrefixTokens(dist: TokenProb[], k: number): TokenProb[] {
  // Sort by probability descending, then by token string for deterministic ordering
  const sortedDist = [...dist].sort((a, b) => {
    if (b.prob !== a.prob) return b.prob - a.prob;
    return a.token.localeCompare(b.token);
  });

  // Get all non-empty tokens
  const allTokens = new Set(sortedDist.filter((t) => t.token).map((t) => t.token));

  const topK: TokenProb[] = [];
  for (const t of sortedDist) {
    if (!t.token) continue;

    // Skip if this token is a prefix of another token
    let isPrefix = false;
    for (const other of allTokens) {
      if (other !== t.token && other.startsWith(t.token)) {
        isPrefix = true;
        break;
      }
    }

    if (!isPrefix) {
      topK.push(t);
    }
    if (topK.length >= k) break;
  }

  return topK;
}

/**
 * Find the longest token matching the start of text.
 * @returns Tuple of [matched TokenProb or null, index in tokens list or -1]
 */
export function findLongestMatch(
  text: string,
  tokens: TokenProb[]
): [TokenProb | null, number] {
  let matchedToken: TokenProb | null = null;
  let matchedIndex = -1;
  let bestLen = 0;

  for (let idx = 0; idx < tokens.length; idx++) {
    const tp = tokens[idx];
    if (text.startsWith(tp.token) && tp.token.length > bestLen) {
      matchedToken = tp;
      matchedIndex = idx;
      bestLen = tp.token.length;
    }
  }

  return [matchedToken, matchedIndex];
}

/**
 * Find knock sequence in list of token indices.
 * @returns Start position of knock sequence, or -1 if not found
 */
export function findKnockSequence(indices: number[], knock: number[]): number {
  if (!knock.length || !indices.length) return -1;

  const knockLen = knock.length;
  for (let i = 0; i <= indices.length - knockLen; i++) {
    let match = true;
    for (let j = 0; j < knockLen; j++) {
      if (indices[i + j] !== knock[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

/**
 * Check if knock sequence would appear in encoded payload.
 */
export function checkKnockInData(
  dataBits: number[],
  knock: number[],
  bitsPerToken: number
): boolean {
  if (!knock.length || !dataBits.length) return false;

  // Convert data bits to token indices
  const indices: number[] = [];
  for (let i = 0; i < dataBits.length; i += bitsPerToken) {
    const chunk = dataBits.slice(i, i + bitsPerToken);
    // Pad if needed
    while (chunk.length < bitsPerToken) {
      chunk.push(0);
    }
    // Convert to index
    let value = 0;
    for (const bit of chunk) {
      value = (value << 1) | bit;
    }
    indices.push(value);
  }

  return findKnockSequence(indices, knock) !== -1;
}

/**
 * Sample a token from distribution using temperature-scaled probabilities.
 * @returns Tuple of [index, token_string]
 */
export function sampleFromDistribution(
  topK: TokenProb[],
  temperature: number = 1.0
): [number, string] {
  if (!topK.length) return [0, ''];

  if (temperature <= 0 || topK.length === 1) {
    // Greedy
    return [0, topK[0].token];
  }

  // Apply temperature scaling to probabilities
  const probs = topK.map((t) => t.prob);

  // Temperature scaling (in log space for numerical stability)
  const scaled = probs.map((p) => Math.pow(p, 1.0 / temperature));
  const total = scaled.reduce((a, b) => a + b, 0);

  if (total <= 0) return [0, topK[0].token];

  const normalized = scaled.map((p) => p / total);

  // Sample
  const r = Math.random();
  let cumulative = 0.0;
  for (let i = 0; i < normalized.length; i++) {
    cumulative += normalized[i];
    if (r < cumulative) {
      return [i, topK[i].token];
    }
  }

  return [topK.length - 1, topK[topK.length - 1].token];
}
