/**
 * Arithmetic coding for steganographic token selection.
 *
 * This module implements arithmetic coding for LLM steganography, where:
 * - Message bits are encoded into token selections
 * - Tokens are selected proportionally to their natural probability
 * - This makes the output statistically indistinguishable from normal LLM generation
 */

import type { TokenProb } from './types.ts';

// 32-bit precision for cross-language compatibility
export const PRECISION = 32;
export const FULL_RANGE = 1 << PRECISION; // 2^32 = 4294967296
export const HALF = FULL_RANGE >>> 1; // 2^31
export const QUARTER = HALF >>> 1; // 2^30
export const MASK = (FULL_RANGE - 1) >>> 0; // Ensure unsigned

/**
 * Cumulative probability range for a token.
 */
export interface CumulativeRange {
  token: TokenProb;
  low: number; // Inclusive
  high: number; // Exclusive
}

/**
 * Arithmetic coding state for steganographic encoding/decoding.
 */
export interface ArithState {
  low: number;
  high: number;
}

/**
 * Create initial arithmetic state.
 */
export function createArithState(): ArithState {
  return {
    low: 0,
    high: MASK, // FULL_RANGE - 1
  };
}

/**
 * Convert token probabilities to integer cumulative ranges.
 *
 * Uses integer arithmetic to ensure encoder/decoder produce identical results
 * regardless of floating-point precision differences.
 */
export function normalizeDistribution(topK: TokenProb[]): CumulativeRange[] {
  if (topK.length === 0) {
    return [];
  }

  // Sum probabilities for normalization
  let totalProb = 0;
  for (const t of topK) {
    totalProb += t.prob;
  }

  let uniformProb: number | null = null;
  if (totalProb <= 0) {
    // Fallback to uniform distribution
    totalProb = topK.length;
    uniformProb = 1.0;
  }

  const ranges: CumulativeRange[] = [];
  let cumulative = 0;

  for (let i = 0; i < topK.length; i++) {
    const token = topK[i];

    // Calculate integer range for this token
    let intRange: number;
    if (uniformProb !== null) {
      // Uniform fallback
      intRange = Math.floor(FULL_RANGE / topK.length);
    } else {
      // Proportional to probability
      intRange = Math.floor((token.prob / totalProb) * FULL_RANGE);
    }

    // Ensure minimum range of 1 to avoid degenerate intervals
    intRange = Math.max(1, intRange);

    // Last token gets remaining range to avoid rounding errors
    if (i === topK.length - 1) {
      intRange = FULL_RANGE - cumulative;
    }

    ranges.push({
      token,
      low: cumulative,
      high: cumulative + intRange,
    });
    cumulative += intRange;
  }

  return ranges;
}

/**
 * Select a token using probability-weighted encoding.
 *
 * This simplified approach:
 * 1. Reads log2(K) bits to get an index in [0, K)
 * 2. Maps that index through cumulative probability ranges
 * 3. Selects the token at the mapped position
 *
 * The result is that tokens are selected proportionally to probability
 * while maintaining a fixed bit rate (same as uniform encoding).
 *
 * If entropyThreshold > 0 and the top token's probability exceeds it,
 * we skip encoding and just emit the top token (0 bits consumed).
 * This makes output more natural when one token is overwhelmingly likely.
 *
 * @returns [selected_token, new_bit_index, new_state]
 */
export function encodeToken(
  bitStream: number[],
  bitIndex: number,
  state: ArithState,
  topK: TokenProb[],
  entropyThreshold: number = 0.0
): [TokenProb, number, ArithState] {
  if (topK.length === 0) {
    throw new Error('Empty token distribution');
  }

  // Check entropy threshold - if top token is very likely, just emit it
  // without encoding any bits. Both encoder and decoder detect this.
  if (entropyThreshold > 0) {
    let totalProb = 0;
    for (const t of topK) {
      totalProb += t.prob;
    }
    if (totalProb > 0) {
      const topProb = topK[0].prob / totalProb;
      if (topProb >= entropyThreshold) {
        // Skip encoding - emit top token, consume 0 bits
        return [topK[0], bitIndex, state];
      }
    }
  }

  const k = topK.length;
  const bitsPerToken = k > 1 ? Math.floor(Math.log2(k)) : 1;

  // Read fixed number of bits
  const remainingBits = bitStream.length - bitIndex;
  const bitsToRead = Math.min(bitsPerToken, remainingBits);

  // Build index value from bits
  let index = 0;
  for (let i = 0; i < bitsToRead; i++) {
    if (bitIndex + i < bitStream.length) {
      index = (index << 1) | bitStream[bitIndex + i];
    } else {
      index = index << 1;
    }
  }

  // Pad if needed
  if (bitsToRead < bitsPerToken) {
    index = index << (bitsPerToken - bitsToRead);
  }

  // Wrap index if needed
  if (index >= k) {
    index = index % k;
  }

  // Select token at this index (same as uniform encoding)
  const selectedToken = topK[index];

  return [selectedToken, bitIndex + bitsToRead, state];
}

/**
 * Extract message bits encoded by a token selection.
 *
 * Given the token that was selected, find its index and convert to bits.
 *
 * If entropyThreshold > 0 and the top token's probability exceeds it,
 * we assume 0 bits were encoded (encoder skipped this position).
 *
 * @returns [extracted_bits, new_state]
 */
export function decodeToken(
  token: TokenProb,
  state: ArithState,
  topK: TokenProb[],
  entropyThreshold: number = 0.0
): [number[], ArithState] {
  if (topK.length === 0) {
    throw new Error('Empty token distribution');
  }

  // Check entropy threshold - if top token is very likely, encoder skipped this position
  if (entropyThreshold > 0) {
    let totalProb = 0;
    for (const t of topK) {
      totalProb += t.prob;
    }
    if (totalProb > 0) {
      const topProb = topK[0].prob / totalProb;
      if (topProb >= entropyThreshold) {
        // No bits were encoded at this position
        return [[], state];
      }
    }
  }

  const k = topK.length;
  const bitsPerToken = k > 1 ? Math.floor(Math.log2(k)) : 1;

  // Find the token's index
  let index: number | null = null;
  for (let i = 0; i < topK.length; i++) {
    if (topK[i].token === token.token) {
      index = i;
      break;
    }
  }

  if (index === null) {
    throw new Error(`Token '${token.token}' not found in distribution`);
  }

  // Convert index to bits
  const bitsExtracted: number[] = [];
  for (let i = bitsPerToken - 1; i >= 0; i--) {
    const bit = (index >> i) & 1;
    bitsExtracted.push(bit);
  }

  return [bitsExtracted, state];
}
