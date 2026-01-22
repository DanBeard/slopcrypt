/**
 * Steganography encoding/decoding with knock sequences.
 * Port of stego_basek.py lines 147-503.
 */

import type { LMClient, Secret } from './types.ts';
import { NONCE_SIZE, DEFAULT_PROMPT } from './types.ts';
import { bytesToBits, bitsToBytes, bitsToInt, intToBits } from './bits.ts';
import {
  filterPrefixTokens,
  findLongestMatch,
  findKnockSequence,
  checkKnockInData,
  sampleFromDistribution,
} from './tokens.ts';
import { compressPayload, decompressPayload, DEFAULT_FREQUENCIES } from './huffman.ts';
import { encryptPayload, decryptPayload } from './crypto.ts';

/**
 * Progress callback for long-running operations.
 */
export type ProgressCallback = (phase: string, current: number, total: number) => void;

/**
 * Encode binary data with knock sequence for natural-looking cover text.
 *
 * 1. Generate preamble_tokens naturally (sampling)
 * 2. Encode knock sequence
 * 3. Encode length + payload
 * 4. Generate suffix_tokens naturally
 */
export async function encodeWithKnock(
  data: Uint8Array,
  client: LMClient,
  prompt: string,
  k: number,
  knock: number[],
  preambleTokens: number = 4,
  suffixTokens: number = 2,
  temperature: number = 0.8,
  onProgress?: ProgressCallback
): Promise<string> {
  const bitsPerToken = Math.log2(k);

  // Prepend 4-byte length header
  const lengthHeader = new Uint8Array(4);
  lengthHeader[0] = (data.length >> 24) & 0xff;
  lengthHeader[1] = (data.length >> 16) & 0xff;
  lengthHeader[2] = (data.length >> 8) & 0xff;
  lengthHeader[3] = data.length & 0xff;

  const fullData = new Uint8Array(lengthHeader.length + data.length);
  fullData.set(lengthHeader);
  fullData.set(data, lengthHeader.length);

  const bitStream = bytesToBits(fullData);

  // Check if knock sequence would appear in payload
  if (checkKnockInData(bitStream, knock, bitsPerToken)) {
    throw new Error(
      'Knock sequence would appear in encoded payload, use different knock sequence'
    );
  }

  let context = prompt;
  const tokens: string[] = [];

  // Phase 1: Generate preamble naturally (sampling)
  onProgress?.('Generating preamble', 0, preambleTokens);
  const preambleIndices: number[] = [];

  for (let i = 0; i < preambleTokens; i++) {
    const dist = await client.getTokenDistribution(context);
    if (!dist.length) break;

    const topK = filterPrefixTokens(dist, k);
    if (!topK.length) break;

    const [idx, token] = sampleFromDistribution(topK, temperature);
    tokens.push(token);
    preambleIndices.push(idx);
    context += token;
    onProgress?.('Generating preamble', i + 1, preambleTokens);
  }

  // Check if knock sequence appears in preamble
  if (findKnockSequence(preambleIndices, knock) !== -1) {
    throw new Error(
      'Knock sequence found in preamble, use different knock sequence or prompt'
    );
  }

  // Phase 2: Encode knock sequence
  onProgress?.('Encoding knock', 0, knock.length);

  for (let i = 0; i < knock.length; i++) {
    const idx = knock[i];
    const dist = await client.getTokenDistribution(context);
    if (!dist.length) {
      throw new Error('Empty distribution while encoding knock sequence');
    }

    const topK = filterPrefixTokens(dist, k);
    if (!topK.length) {
      throw new Error('No valid tokens while encoding knock sequence');
    }

    const actualIdx = idx >= topK.length ? idx % topK.length : idx;
    const token = topK[actualIdx].token;
    tokens.push(token);
    context += token;
    onProgress?.('Encoding knock', i + 1, knock.length);
  }

  // Phase 3: Encode length + payload
  const totalPayloadTokens = Math.ceil(bitStream.length / bitsPerToken);
  onProgress?.('Encoding payload', 0, totalPayloadTokens);

  let bitIdx = 0;
  let payloadTokenCount = 0;

  while (bitIdx < bitStream.length) {
    const chunk = bitStream.slice(bitIdx, bitIdx + bitsPerToken);
    while (chunk.length < bitsPerToken) {
      chunk.push(0);
    }

    const index = bitsToInt(chunk);

    const dist = await client.getTokenDistribution(context);
    if (!dist.length) break;

    const topK = filterPrefixTokens(dist, k);
    if (!topK.length) break;

    const actualIndex = index >= topK.length ? index % topK.length : index;
    const token = topK[actualIndex].token;
    tokens.push(token);
    context += token;
    bitIdx += bitsPerToken;
    payloadTokenCount++;

    if (payloadTokenCount % 10 === 0) {
      onProgress?.('Encoding payload', payloadTokenCount, totalPayloadTokens);
    }
  }

  // Phase 4: Generate suffix naturally (sampling)
  onProgress?.('Generating suffix', 0, suffixTokens);

  for (let i = 0; i < suffixTokens; i++) {
    const dist = await client.getTokenDistribution(context);
    if (!dist.length) break;

    const topK = filterPrefixTokens(dist, k);
    if (!topK.length) break;

    const [, token] = sampleFromDistribution(topK, temperature);
    tokens.push(token);
    context += token;
    onProgress?.('Generating suffix', i + 1, suffixTokens);
  }

  onProgress?.('Complete', 1, 1);

  // Return prompt + generated tokens as complete cover text
  return prompt + tokens.join('');
}

/**
 * Decode binary data from cover text with knock sequence.
 */
export async function decodeWithKnock(
  coverText: string,
  client: LMClient,
  k: number,
  knock: number[],
  prompt: string = '',
  onProgress?: ProgressCallback
): Promise<Uint8Array> {
  const bitsPerToken = Math.log2(k);

  // If prompt provided and coverText starts with it, strip prompt
  let context: string;
  let remaining: string;

  if (prompt && coverText.startsWith(prompt)) {
    context = prompt;
    remaining = coverText.slice(prompt.length);
  } else {
    context = '';
    remaining = coverText;
  }

  const tokenIndices: number[] = [];
  let tokenCount = 0;

  // Phase 1: Scan all tokens and collect indices
  onProgress?.('Scanning tokens', 0, remaining.length);

  while (remaining.length > 0) {
    const dist = await client.getTokenDistribution(context);
    if (!dist.length) {
      context += remaining[0];
      remaining = remaining.slice(1);
      continue;
    }

    const topK = filterPrefixTokens(dist, k);
    if (!topK.length) {
      context += remaining[0];
      remaining = remaining.slice(1);
      continue;
    }

    const [matched, matchedIndex] = findLongestMatch(remaining, topK);

    if (matched === null) {
      context += remaining[0];
      remaining = remaining.slice(1);
      continue;
    }

    tokenIndices.push(matchedIndex);
    context += matched.token;
    remaining = remaining.slice(matched.token.length);
    tokenCount++;

    if (tokenCount % 20 === 0) {
      onProgress?.('Scanning tokens', coverText.length - remaining.length, coverText.length);
    }
  }

  // Phase 2: Find knock sequence
  const knockPos = findKnockSequence(tokenIndices, knock);

  if (knockPos === -1) {
    throw new Error('Knock sequence not found in cover text');
  }

  // Phase 3: Extract payload indices (after knock)
  const payloadStart = knockPos + knock.length;
  const payloadIndices = tokenIndices.slice(payloadStart);

  onProgress?.('Decoding payload', 0, payloadIndices.length);

  // Phase 4: Convert indices to bits
  const bits: number[] = [];

  for (let i = 0; i < payloadIndices.length; i++) {
    const idx = payloadIndices[i];
    const tokenBits = intToBits(idx, bitsPerToken);
    bits.push(...tokenBits);

    // Check if we have enough bits to read the length header
    if (bits.length >= 32) {
      const lengthBits = bits.slice(0, 32);
      const payloadLen = bitsToInt(lengthBits);
      const totalBitsNeeded = 32 + payloadLen * 8;

      if (bits.length >= totalBitsNeeded) {
        break;
      }
    }

    if (i % 20 === 0) {
      onProgress?.('Decoding payload', i, payloadIndices.length);
    }
  }

  onProgress?.('Complete', 1, 1);

  // Convert bits to bytes
  const allBytes = bitsToBytes(bits);

  if (allBytes.length < 4) {
    return new Uint8Array(0);
  }

  // Extract length and payload
  let payloadLen = (allBytes[0] << 24) | (allBytes[1] << 16) | (allBytes[2] << 8) | allBytes[3];

  if (payloadLen > allBytes.length - 4) {
    payloadLen = allBytes.length - 4;
  }

  return allBytes.slice(4, 4 + payloadLen);
}

/**
 * High-level encode: message -> compress -> encrypt -> encode into cover text
 */
export async function encodeMessage(
  message: Uint8Array,
  secret: Secret,
  client: LMClient,
  prompt: string = DEFAULT_PROMPT,
  compress: boolean = true,
  onProgress?: ProgressCallback
): Promise<string> {
  const frequencies = secret.huffman_freq || DEFAULT_FREQUENCIES;

  // Step 1: Compress if enabled
  let compressed: Uint8Array;
  let compType: number;

  if (compress) {
    [compressed, compType] = compressPayload(message, frequencies);
  } else {
    compressed = message;
    compType = 0; // COMPRESSION_NONE
  }

  // Prepend compression type byte
  const compressedWithHeader = new Uint8Array(1 + compressed.length);
  compressedWithHeader[0] = compType;
  compressedWithHeader.set(compressed, 1);

  // Step 2: Encrypt the compressed data
  const encrypted = await encryptPayload(compressedWithHeader, secret.payload_key);

  // Step 3: Encode using stego
  const coverText = await encodeWithKnock(
    encrypted,
    client,
    prompt,
    secret.k,
    secret.knock,
    secret.preamble_tokens,
    secret.suffix_tokens,
    secret.temperature,
    onProgress
  );

  return coverText;
}

/**
 * High-level decode: decode from cover text -> decrypt -> decompress -> message
 */
export async function decodeMessage(
  coverText: string,
  secret: Secret,
  client: LMClient,
  prompt: string = '',
  onProgress?: ProgressCallback
): Promise<Uint8Array> {
  // Step 1: Decode using stego
  const encryptedPayload = await decodeWithKnock(
    coverText,
    client,
    secret.k,
    secret.knock,
    prompt,
    onProgress
  );

  if (encryptedPayload.length < NONCE_SIZE + 16 + 1) {
    throw new Error('Decoded payload too short');
  }

  // Step 2: Decrypt
  const decrypted = await decryptPayload(encryptedPayload, secret.payload_key);

  if (decrypted.length < 1) {
    throw new Error('Decrypted payload too short');
  }

  // Step 3: Extract compression type and decompress
  const compType = decrypted[0];
  const compressed = decrypted.slice(1);

  const frequencies = secret.huffman_freq || DEFAULT_FREQUENCIES;
  const message = decompressPayload(compressed, compType, frequencies);

  return message;
}
