/**
 * Integration tests for WllamaClient encode/decode roundtrip.
 *
 * These tests use the actual wllama model and are slow (~30s+ for model load).
 * They are skipped by default in CI. Run with:
 *   WLLAMA_TEST=1 npm test
 *
 * Or run just this file:
 *   WLLAMA_TEST=1 npx vitest run test/wllama-integration.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { webcrypto } from 'crypto';

// Polyfill crypto for Node.js environment
if (typeof globalThis.crypto === 'undefined') {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

// Skip these tests unless WLLAMA_TEST env var is set
const SKIP_WLLAMA = !process.env.WLLAMA_TEST;

import { WllamaClient, AVAILABLE_MODELS } from '../src/wllama-client.ts';
import { generateSecret } from '../src/secret.ts';
import { encodeWithKnock, decodeWithKnock, encodeMessage, decodeMessage } from '../src/stego.ts';
import { filterPrefixTokens } from '../src/tokens.ts';

describe.skipIf(SKIP_WLLAMA)('WllamaClient Integration', () => {
  let client: WllamaClient;

  beforeAll(async () => {
    // Use smallest model for faster tests
    const smallestModel = AVAILABLE_MODELS[0]; // SmolLM2-135M
    client = new WllamaClient(64, smallestModel);

    console.log(`Loading model: ${smallestModel.name}...`);
    await client.loadModel((progress) => {
      if (progress % 0.25 < 0.01) {
        console.log(`  Loading: ${Math.round(progress * 100)}%`);
      }
    });
    console.log('Model loaded!');
  }, 120000); // 2 minute timeout for model loading

  afterAll(async () => {
    if (client) {
      await client.close();
    }
  });

  describe('Token Distribution', () => {
    it('returns consistent distribution for same context', async () => {
      client.resetContext();
      const dist1 = await client.getTokenDistribution('Hello');

      client.resetContext();
      const dist2 = await client.getTokenDistribution('Hello');

      // Top tokens should be the same
      expect(dist1.slice(0, 5).map(t => t.token)).toEqual(
        dist2.slice(0, 5).map(t => t.token)
      );
    });

    it('handles incremental context correctly', async () => {
      client.resetContext();

      // Build up context incrementally
      const dist1 = await client.getTokenDistribution('The');
      const dist2 = await client.getTokenDistribution('The quick');
      const dist3 = await client.getTokenDistribution('The quick brown');

      // Each should return valid distributions
      expect(dist1.length).toBeGreaterThan(0);
      expect(dist2.length).toBeGreaterThan(0);
      expect(dist3.length).toBeGreaterThan(0);
    });

    it('handles character-by-character context build-up', async () => {
      // This tests the fix for the incremental inference bug
      client.resetContext();

      // Simulate decode's character-by-character fallback
      await client.getTokenDistribution('T');
      await client.getTokenDistribution('Th');
      await client.getTokenDistribution('The');
      const distCharByChar = await client.getTokenDistribution('The ');

      // Compare with direct context
      client.resetContext();
      const distDirect = await client.getTokenDistribution('The ');

      // Top tokens should match (verifies the incremental fix works)
      const topCharByChar = distCharByChar.slice(0, 10).map(t => t.token);
      const topDirect = distDirect.slice(0, 10).map(t => t.token);

      // At least the top few should match
      const overlap = topCharByChar.filter(t => topDirect.includes(t));
      expect(overlap.length).toBeGreaterThanOrEqual(5);
    });
  });

  describe('Low-level encodeWithKnock/decodeWithKnock', () => {
    it('roundtrips a short message', async () => {
      client.resetContext();

      const data = new TextEncoder().encode('Hi');
      const prompt = 'Say: ';
      const k = 16;
      const knock = [0, 1, 2, 3, 4, 5];

      console.log('Encoding...');
      const coverText = await encodeWithKnock(
        data, client, prompt, k, knock, 2, 1, 0.8
      );
      console.log('Cover text:', coverText.slice(0, 100) + '...');

      client.resetContext();

      console.log('Decoding...');
      const decoded = await decodeWithKnock(
        coverText, client, k, knock, ''  // No prompt - tests knock detection
      );

      expect(decoded).toEqual(data);
    }, 60000);

    it('roundtrips with prompt provided to decode', async () => {
      client.resetContext();

      const data = new TextEncoder().encode('Test');
      const prompt = 'Message: ';
      const k = 16;
      const knock = [5, 10, 3, 8];

      const coverText = await encodeWithKnock(
        data, client, prompt, k, knock, 3, 2, 0.8
      );

      client.resetContext();

      // Provide prompt to decode (should also work)
      const decoded = await decodeWithKnock(
        coverText, client, k, knock, prompt
      );

      expect(decoded).toEqual(data);
    }, 60000);
  });

  describe('High-level encodeMessage/decodeMessage', () => {
    it('roundtrips with compression', async () => {
      client.resetContext();

      const secret = generateSecret({
        k: 16,
        knock: [0, 1, 2, 3, 4, 5],
        preambleTokens: 2,
        suffixTokens: 1,
      });

      const message = new TextEncoder().encode('Hello!');
      const prompt = 'Note: ';

      console.log('Encoding message...');
      const coverText = await encodeMessage(
        message, secret, client, prompt, true
      );
      console.log('Cover text length:', coverText.length);

      client.resetContext();

      console.log('Decoding message...');
      const decoded = await decodeMessage(
        coverText, secret, client, ''  // No prompt
      );

      expect(decoded).toEqual(message);
    }, 90000);

    it('roundtrips without compression', async () => {
      client.resetContext();

      const secret = generateSecret({
        k: 16,
        knock: [3, 7, 2, 9, 4, 1],
        preambleTokens: 2,
        suffixTokens: 1,
      });

      const message = new TextEncoder().encode('Test');
      const prompt = 'Data: ';

      const coverText = await encodeMessage(
        message, secret, client, prompt, false  // No compression
      );

      client.resetContext();

      const decoded = await decodeMessage(
        coverText, secret, client, ''
      );

      expect(decoded).toEqual(message);
    }, 90000);
  });

  describe('Edge Cases', () => {
    it('handles empty message', async () => {
      client.resetContext();

      const secret = generateSecret({
        k: 16,
        knock: [0, 1, 2, 3, 4, 5],
        preambleTokens: 2,
        suffixTokens: 1,
      });

      const message = new Uint8Array(0);
      const prompt = 'Empty: ';

      const coverText = await encodeMessage(
        message, secret, client, prompt, true
      );

      client.resetContext();

      const decoded = await decodeMessage(
        coverText, secret, client, ''
      );

      expect(decoded).toEqual(message);
    }, 60000);

    it('handles single byte message', async () => {
      client.resetContext();

      const secret = generateSecret({
        k: 16,
        knock: [1, 2, 3, 4, 5, 6],
        preambleTokens: 2,
        suffixTokens: 1,
      });

      const message = new Uint8Array([0x42]); // 'B'
      const prompt = 'Byte: ';

      const coverText = await encodeMessage(
        message, secret, client, prompt, false
      );

      client.resetContext();

      const decoded = await decodeMessage(
        coverText, secret, client, ''
      );

      expect(decoded).toEqual(message);
    }, 60000);
  });
});
