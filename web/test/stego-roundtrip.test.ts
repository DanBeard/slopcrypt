/**
 * Detailed roundtrip tests for steganography encode/decode.
 * Tests to identify issues with knock sequence detection.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { webcrypto } from 'crypto';

// Polyfill crypto for Node.js environment
if (typeof globalThis.crypto === 'undefined') {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

import { FixedDistributionClient } from '../src/fixed-client.ts';
import { generateSecret } from '../src/secret.ts';
import { encodeWithKnock, decodeWithKnock, encodeMessage, decodeMessage } from '../src/stego.ts';
import { encryptPayload } from '../src/crypto.ts';
import { bytesToBits, bitsToBytes, intToBits, bitsToInt } from '../src/bits.ts';
import { filterPrefixTokens, findKnockSequence } from '../src/tokens.ts';
import { encodeToken, decodeToken, createArithState } from '../src/arith-stego.ts';

describe('Low-level encodeWithKnock/decodeWithKnock', () => {
  it('roundtrips small data with k=16', async () => {
    const client = new FixedDistributionClient(32);
    const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const prompt = 'Test: ';
    const k = 16;
    const knock = [0, 1, 2, 3, 4, 5];

    const coverText = await encodeWithKnock(data, client, prompt, k, knock, 4, 2, 0.8);
    const decoded = await decodeWithKnock(coverText, client, k, knock, prompt);

    expect(decoded).toEqual(data);
  });

  it('roundtrips with k=4', async () => {
    const client = new FixedDistributionClient(32);
    const data = new Uint8Array([0x41, 0x42]); // "AB"
    const prompt = 'Test: ';
    const k = 4;
    const knock = [0, 1, 2, 3];

    const coverText = await encodeWithKnock(data, client, prompt, k, knock, 4, 2, 0.8);
    const decoded = await decodeWithKnock(coverText, client, k, knock, prompt);

    expect(decoded).toEqual(data);
  });

  it('roundtrips with k=8', async () => {
    const client = new FixedDistributionClient(32);
    const data = new Uint8Array([0x48, 0x49]); // "HI"
    const prompt = 'Test: ';
    const k = 8;
    const knock = [0, 1, 2, 3, 4, 5];

    const coverText = await encodeWithKnock(data, client, prompt, k, knock, 4, 2, 0.8);
    const decoded = await decodeWithKnock(coverText, client, k, knock, prompt);

    expect(decoded).toEqual(data);
  });

  it('roundtrips longer message', async () => {
    const client = new FixedDistributionClient(32);
    const message = 'The quick brown fox jumps over the lazy dog.';
    const data = new TextEncoder().encode(message);
    const prompt = 'Story: ';
    const k = 16;
    const knock = [5, 10, 3, 8, 12, 1];

    const coverText = await encodeWithKnock(data, client, prompt, k, knock, 4, 2, 0.8);
    const decoded = await decodeWithKnock(coverText, client, k, knock, prompt);

    expect(decoded).toEqual(data);
  });
});

describe('Knock sequence detection', () => {
  it('finds knock in token indices', () => {
    const indices = [0, 1, 5, 10, 3, 8, 12, 1, 7, 9];
    const knock = [5, 10, 3, 8, 12, 1];

    const pos = findKnockSequence(indices, knock);
    expect(pos).toBe(2);
  });

  it('returns -1 when knock not found', () => {
    const indices = [0, 1, 2, 3, 4, 5, 6, 7];
    const knock = [5, 10, 3, 8, 12, 1];

    const pos = findKnockSequence(indices, knock);
    expect(pos).toBe(-1);
  });
});

describe('Arithmetic encode/decode token', () => {
  it('roundtrips single token', () => {
    const topK = [
      { token: 'a', prob: 0.5 },
      { token: 'b', prob: 0.3 },
      { token: 'c', prob: 0.15 },
      { token: 'd', prob: 0.05 },
    ];

    const bits = [1, 0]; // Should select index 2 with k=4
    let state = createArithState();

    const [selectedToken, newIdx, newState] = encodeToken(bits, 0, state, topK);
    expect(selectedToken.token).toBe('c'); // Index 2
    expect(newIdx).toBe(2); // Consumed 2 bits (log2(4) = 2)

    // Decode
    const [decodedBits, _] = decodeToken(selectedToken, createArithState(), topK);
    expect(decodedBits).toEqual([1, 0]);
  });

  it('handles k=16 tokens', () => {
    const topK = Array.from({ length: 16 }, (_, i) => ({
      token: `t${i}`,
      prob: 0.1 - i * 0.005,
    }));

    // Test various bit patterns
    const testCases = [
      [0, 0, 0, 0], // Index 0
      [0, 0, 0, 1], // Index 1
      [1, 1, 1, 1], // Index 15
      [1, 0, 1, 0], // Index 10
    ];

    for (const bits of testCases) {
      const state = createArithState();
      const [selectedToken, newIdx, _] = encodeToken(bits, 0, state, topK);

      const expectedIndex = bitsToInt(bits);
      expect(selectedToken.token).toBe(`t${expectedIndex}`);

      // Decode
      const [decodedBits, __] = decodeToken(selectedToken, createArithState(), topK);
      expect(decodedBits).toEqual(bits);
    }
  });
});

describe('filterPrefixTokens consistency', () => {
  it('returns exactly k tokens when available', async () => {
    const client = new FixedDistributionClient(32);
    const dist = await client.getTokenDistribution('test');

    const filtered16 = filterPrefixTokens(dist, 16);
    const filtered8 = filterPrefixTokens(dist, 8);
    const filtered4 = filterPrefixTokens(dist, 4);

    expect(filtered16.length).toBe(16);
    expect(filtered8.length).toBe(8);
    expect(filtered4.length).toBe(4);
  });

  it('returns same tokens for same context', async () => {
    const client = new FixedDistributionClient(32);

    const dist1 = await client.getTokenDistribution('test context');
    const dist2 = await client.getTokenDistribution('test context');

    const filtered1 = filterPrefixTokens(dist1, 16);
    const filtered2 = filterPrefixTokens(dist2, 16);

    expect(filtered1).toEqual(filtered2);
  });
});

describe('Length header encoding', () => {
  it('encodes and decodes length correctly for k=16', () => {
    const bitsPerToken = Math.log2(16); // 4
    const length = 42;

    // Encode length as 4 bytes big-endian
    const lengthHeader = new Uint8Array(4);
    lengthHeader[0] = (length >> 24) & 0xff;
    lengthHeader[1] = (length >> 16) & 0xff;
    lengthHeader[2] = (length >> 8) & 0xff;
    lengthHeader[3] = length & 0xff;

    const lengthBits = bytesToBits(lengthHeader);
    expect(lengthBits.length).toBe(32);

    // Number of tokens needed
    const lengthTokens = Math.ceil(32 / bitsPerToken);
    expect(lengthTokens).toBe(8);

    // Simulate encoding
    const indices: number[] = [];
    let bitIdx = 0;
    while (bitIdx < lengthBits.length) {
      const chunk = lengthBits.slice(bitIdx, bitIdx + bitsPerToken);
      while (chunk.length < bitsPerToken) {
        chunk.push(0);
      }
      indices.push(bitsToInt(chunk));
      bitIdx += bitsPerToken;
    }
    expect(indices.length).toBe(8);

    // Simulate decoding
    const decodedBits: number[] = [];
    for (const idx of indices) {
      const bits = intToBits(idx, bitsPerToken);
      decodedBits.push(...bits);
    }

    const decodedBytes = bitsToBytes(decodedBits.slice(0, 32));
    const decodedLength = (decodedBytes[0] << 24) | (decodedBytes[1] << 16) |
                          (decodedBytes[2] << 8) | decodedBytes[3];

    expect(decodedLength).toBe(length);
  });

  it('encodes and decodes length correctly for k=8', () => {
    const bitsPerToken = Math.log2(8); // 3
    const length = 100;

    const lengthHeader = new Uint8Array(4);
    lengthHeader[0] = (length >> 24) & 0xff;
    lengthHeader[1] = (length >> 16) & 0xff;
    lengthHeader[2] = (length >> 8) & 0xff;
    lengthHeader[3] = length & 0xff;

    const lengthBits = bytesToBits(lengthHeader);

    // Number of tokens needed: ceil(32/3) = 11
    const lengthTokens = Math.ceil(32 / bitsPerToken);
    expect(lengthTokens).toBe(11);

    // Simulate encoding
    const indices: number[] = [];
    let bitIdx = 0;
    while (bitIdx < lengthBits.length) {
      const chunk = lengthBits.slice(bitIdx, bitIdx + bitsPerToken);
      while (chunk.length < bitsPerToken) {
        chunk.push(0);
      }
      indices.push(bitsToInt(chunk));
      bitIdx += bitsPerToken;
    }
    expect(indices.length).toBe(11);

    // Simulate decoding
    const decodedBits: number[] = [];
    for (const idx of indices) {
      const bits = intToBits(idx, bitsPerToken);
      decodedBits.push(...bits);
    }

    const decodedBytes = bitsToBytes(decodedBits.slice(0, 32));
    const decodedLength = (decodedBytes[0] << 24) | (decodedBytes[1] << 16) |
                          (decodedBytes[2] << 8) | decodedBytes[3];

    expect(decodedLength).toBe(length);
  });
});

describe('Full message roundtrip with various secrets', () => {
  it('works with k=4', async () => {
    const client = new FixedDistributionClient(32);
    const secret = generateSecret({
      k: 4,
      knock: [0, 1, 2, 3],
      preambleTokens: 4,
      suffixTokens: 2,
    });

    const message = new TextEncoder().encode('Test k=4');
    const prompt = 'Test: ';

    const coverText = await encodeMessage(message, secret, client, prompt, true);
    const decoded = await decodeMessage(coverText, secret, client, prompt);

    expect(decoded).toEqual(message);
  });

  it('works with k=8', async () => {
    const client = new FixedDistributionClient(32);
    const secret = generateSecret({
      k: 8,
      knock: [0, 1, 2, 3, 4, 5],
      preambleTokens: 4,
      suffixTokens: 2,
    });

    const message = new TextEncoder().encode('Test k=8');
    const prompt = 'Test: ';

    const coverText = await encodeMessage(message, secret, client, prompt, true);
    const decoded = await decodeMessage(coverText, secret, client, prompt);

    expect(decoded).toEqual(message);
  });

  it('works with k=32', async () => {
    const client = new FixedDistributionClient(64);
    const secret = generateSecret({
      k: 32,
      knock: [0, 1, 2, 3, 4, 5, 6, 7],
      preambleTokens: 4,
      suffixTokens: 2,
    });

    const message = new TextEncoder().encode('Test k=32');
    const prompt = 'Test: ';

    const coverText = await encodeMessage(message, secret, client, prompt, true);
    const decoded = await decodeMessage(coverText, secret, client, prompt);

    expect(decoded).toEqual(message);
  });

  it('works without compression', async () => {
    const client = new FixedDistributionClient(32);
    const secret = generateSecret({
      k: 16,
      knock: [0, 1, 2, 3, 4, 5],
      preambleTokens: 4,
      suffixTokens: 2,
    });

    const message = new TextEncoder().encode('No compression test');
    const prompt = 'Test: ';

    const coverText = await encodeMessage(message, secret, client, prompt, false);
    const decoded = await decodeMessage(coverText, secret, client, prompt);

    expect(decoded).toEqual(message);
  });

  it('works with longer messages', async () => {
    const client = new FixedDistributionClient(32);
    const secret = generateSecret({
      k: 16,
      knock: [5, 10, 3, 8, 12, 1],
      preambleTokens: 4,
      suffixTokens: 2,
    });

    const message = new TextEncoder().encode(
      'This is a longer message that should test the encoding properly. ' +
      'It contains multiple sentences and various characters.'
    );
    const prompt = 'Story time: ';

    const coverText = await encodeMessage(message, secret, client, prompt, true);
    const decoded = await decodeMessage(coverText, secret, client, prompt);

    expect(decoded).toEqual(message);
  });
});

describe('Debug: Trace encode/decode steps', () => {
  it('traces knock sequence through encode/decode', async () => {
    const client = new FixedDistributionClient(32);
    const data = new Uint8Array([0x41]); // Single byte
    const prompt = 'Test: ';
    const k = 16;
    const knock = [5, 10, 3];

    // Encode
    const coverText = await encodeWithKnock(data, client, prompt, k, knock, 2, 1, 0.8);

    // Manual decode to trace
    let context = prompt;
    let remaining = coverText.slice(prompt.length);
    const indices: number[] = [];

    while (remaining.length > 0) {
      const dist = await client.getTokenDistribution(context);
      const topK = filterPrefixTokens(dist, k);

      // Find matching token
      let matched = false;
      for (let i = 0; i < topK.length; i++) {
        if (remaining.startsWith(topK[i].token)) {
          indices.push(i);
          context += topK[i].token;
          remaining = remaining.slice(topK[i].token.length);
          matched = true;
          break;
        }
      }

      if (!matched) {
        // Character not in topK, advance by 1
        context += remaining[0];
        remaining = remaining.slice(1);
      }
    }

    // Find knock in indices
    const knockPos = findKnockSequence(indices, knock);
    expect(knockPos).toBeGreaterThanOrEqual(0);

    // Verify the knock indices match
    for (let i = 0; i < knock.length; i++) {
      expect(indices[knockPos + i]).toBe(knock[i]);
    }
  });
});
