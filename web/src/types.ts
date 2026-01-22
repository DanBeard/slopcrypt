/**
 * Shared types for SlopCrypt web implementation.
 */

/**
 * A token with its probability.
 */
export interface TokenProb {
  token: string;
  prob: number;
}

/**
 * LLM client interface for token distribution.
 */
export interface LMClient {
  getTokenDistribution(context: string): Promise<TokenProb[]>;
}

/**
 * Secret blob structure (matches Python msgpack format).
 */
export interface Secret {
  version: number;
  knock: number[];
  k: number;
  payload_key: Uint8Array;
  preamble_tokens: number;
  suffix_tokens: number;
  temperature: number;
  entropy_threshold?: number;
  huffman_freq: Record<number, number>;
  notes: string;
}

/**
 * Compression types.
 */
export const COMPRESSION_NONE = 0;
export const COMPRESSION_HUFFMAN = 1;
export const COMPRESSION_ARITHMETIC = 2;

/**
 * Crypto constants.
 */
export const PBKDF2_ITERATIONS = 600_000;
export const SALT_SIZE = 16;
export const NONCE_SIZE = 12;
export const PAYLOAD_KEY_SIZE = 32;
export const SECRET_VERSION = 2;

/**
 * Default prompt for cover text generation.
 */
export const DEFAULT_PROMPT =
  'Write a short story about a traveler:\n\nThe weary traveler had been walking for';
