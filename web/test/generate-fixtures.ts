/**
 * Generate test fixtures from TypeScript for Python cross-compatibility testing.
 *
 * This script generates JSON fixture files that can be used to verify
 * that Python implementations produce identical results to TypeScript.
 *
 * Usage:
 *   npm run generate-fixtures
 */

import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { webcrypto } from 'crypto';

// Polyfill crypto for Node.js environment
if (typeof globalThis.crypto === 'undefined') {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

import { FixedDistributionClient } from '../src/fixed-client.ts';
import {
  deriveKey,
  encryptPayload,
  bytesToBase64,
  randomBytes,
} from '../src/crypto.ts';
import { encryptSecretBlob, generateSecret } from '../src/secret.ts';
import {
  huffmanEncode,
  compressPayload,
  DEFAULT_FREQUENCIES,
} from '../src/huffman.ts';
import { encodeMessage } from '../src/stego.ts';
import {
  PBKDF2_ITERATIONS,
  PAYLOAD_KEY_SIZE,
  SECRET_VERSION,
  COMPRESSION_HUFFMAN,
  COMPRESSION_NONE,
} from '../src/types.ts';

const FIXTURES_DIR = join(__dirname, '../../tests/fixtures');

// Ensure fixtures directory exists
if (!existsSync(FIXTURES_DIR)) {
  mkdirSync(FIXTURES_DIR, { recursive: true });
}

async function generateCryptoVectors(): Promise<void> {
  console.log('Generating crypto vectors from TypeScript...');

  const pbkdf2Vectors: Array<{
    password: string;
    salt: string;
    expected_key: string;
  }> = [];

  // Test various password/salt combinations
  const testCases = [
    { password: 'test123', salt: '0123456789abcdef' },
    { password: 'password', salt: 'saltsaltsaltsalt' },
    { password: '', salt: 'emptypwd00000000' },
    { password: 'long_password_with_special_chars!@#$%', salt: 'anothersalt12345' },
    { password: '世界', salt: 'unicodepw1234567' },
  ];

  for (const tc of testCases) {
    const salt = new TextEncoder().encode(tc.salt);
    const key = await deriveKey(tc.password, salt);
    const keyBytes = await crypto.subtle.exportKey('raw', key);

    pbkdf2Vectors.push({
      password: tc.password,
      salt: bytesToBase64(salt),
      expected_key: bytesToBase64(new Uint8Array(keyBytes)),
    });
  }

  // Generate AES-GCM vectors
  const aesgcmVectors: Array<{
    key: string;
    plaintext: string;
    ciphertext: string;
  }> = [];

  const testPlaintexts = [
    new TextEncoder().encode('Hello, World!'),
    new Uint8Array(0), // Empty
    new Uint8Array([0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff]), // Binary
    new TextEncoder().encode('Unicode: 世界'),
    new Uint8Array(1000).fill(65), // Larger payload
  ];

  for (const plaintext of testPlaintexts) {
    // Use a fixed key for reproducibility
    const key = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
    const ciphertext = await encryptPayload(plaintext, key);

    aesgcmVectors.push({
      key: bytesToBase64(key),
      plaintext: bytesToBase64(plaintext),
      ciphertext: bytesToBase64(ciphertext),
    });
  }

  const cryptoVectors = {
    pbkdf2_vectors: pbkdf2Vectors,
    aesgcm_vectors: aesgcmVectors,
    generated_by: 'typescript',
  };

  writeFileSync(
    join(FIXTURES_DIR, 'crypto_vectors_ts.json'),
    JSON.stringify(cryptoVectors, null, 2)
  );
  console.log(`  -> ${join(FIXTURES_DIR, 'crypto_vectors_ts.json')}`);
}

async function generateSecretBlobs(): Promise<void> {
  console.log('Generating secret blobs from TypeScript...');

  const blobs: Array<{
    encrypted: string;
    password: string;
    expected: {
      version: number;
      k: number;
      knock: number[];
      preamble_tokens: number;
      suffix_tokens: number;
      temperature: number;
      payload_key_length: number;
    };
  }> = [];

  const testConfigs = [
    {
      k: 16,
      knock: [0, 1, 2, 3, 4, 5],
      password: 'ts_test_password_123',
      preambleTokens: 10,
      suffixTokens: 10,
      temperature: 0.8,
    },
    {
      k: 8,
      knock: [0, 1, 2, 3],
      password: 'short',
      preambleTokens: 5,
      suffixTokens: 5,
      temperature: 0.5,
    },
  ];

  for (const config of testConfigs) {
    const secret = generateSecret({
      k: config.k,
      knock: config.knock,
      preambleTokens: config.preambleTokens,
      suffixTokens: config.suffixTokens,
      temperature: config.temperature,
    });

    const encrypted = await encryptSecretBlob(secret, config.password);

    blobs.push({
      encrypted,
      password: config.password,
      expected: {
        version: secret.version,
        k: secret.k,
        knock: secret.knock,
        preamble_tokens: secret.preamble_tokens,
        suffix_tokens: secret.suffix_tokens,
        temperature: secret.temperature,
        payload_key_length: secret.payload_key.length,
      },
    });
  }

  const secretBlobs = {
    blobs,
    generated_by: 'typescript',
  };

  writeFileSync(
    join(FIXTURES_DIR, 'secret_blobs_ts.json'),
    JSON.stringify(secretBlobs, null, 2)
  );
  console.log(`  -> ${join(FIXTURES_DIR, 'secret_blobs_ts.json')}`);
}

async function generateHuffmanData(): Promise<void> {
  console.log('Generating Huffman data from TypeScript...');

  const compressed: Array<{
    original: string;
    compressed: string;
    compression_type: number;
  }> = [];

  const testData = [
    new TextEncoder().encode('The quick brown fox jumps over the lazy dog.'),
    new TextEncoder().encode('Hello World'.repeat(50)),
    new Uint8Array([0x00, 0xff].concat(Array(18).fill(0x00).concat(Array(18).fill(0xff)))),
    new TextEncoder().encode('Unicode: 世界'),
    new TextEncoder().encode('AAAAAAAAAA'),
    new Uint8Array(0),
    new Uint8Array(Array.from({ length: 95 }, (_, i) => i + 32)), // Printable ASCII
  ];

  for (const data of testData) {
    const [compData, compType] = compressPayload(data, DEFAULT_FREQUENCIES);

    compressed.push({
      original: bytesToBase64(data),
      compressed: bytesToBase64(compData),
      compression_type: compType,
    });
  }

  const huffmanData = {
    compressed,
    default_frequencies: DEFAULT_FREQUENCIES,
    generated_by: 'typescript',
  };

  writeFileSync(
    join(FIXTURES_DIR, 'huffman_data_ts.json'),
    JSON.stringify(huffmanData, null, 2)
  );
  console.log(`  -> ${join(FIXTURES_DIR, 'huffman_data_ts.json')}`);
}

async function generateStegoRoundtrip(): Promise<void> {
  console.log('Generating stego roundtrip data from TypeScript...');

  const client = new FixedDistributionClient(32);

  const encoded: Array<{
    secret_blob: string;
    password: string;
    prompt: string;
    cover_text: string;
    expected_message: string;
  }> = [];

  const testCases = [
    {
      message: new TextEncoder().encode('Secret message from TypeScript'),
      prompt: 'Once upon a time',
      password: 'ts_stego_test_123',
      k: 16,
      knock: [0, 1, 2, 3, 4, 5],
    },
    {
      message: new Uint8Array(0), // Empty message
      prompt: 'Test: ',
      password: 'ts_empty_test',
      k: 16,
      knock: [0, 1, 2, 3, 4, 5],
    },
  ];

  for (const tc of testCases) {
    const secret = generateSecret({
      k: tc.k,
      knock: tc.knock,
      preambleTokens: 5,
      suffixTokens: 5,
      temperature: 0.8,
    });

    const secretBlob = await encryptSecretBlob(secret, tc.password);
    const coverText = await encodeMessage(
      tc.message,
      secret,
      client,
      tc.prompt,
      true
    );

    encoded.push({
      secret_blob: secretBlob,
      password: tc.password,
      prompt: tc.prompt,
      cover_text: coverText,
      expected_message: bytesToBase64(tc.message),
    });
  }

  const stegoRoundtrip = {
    encoded,
    generated_by: 'typescript',
  };

  writeFileSync(
    join(FIXTURES_DIR, 'stego_roundtrip_ts.json'),
    JSON.stringify(stegoRoundtrip, null, 2)
  );
  console.log(`  -> ${join(FIXTURES_DIR, 'stego_roundtrip_ts.json')}`);
}

async function main(): Promise<void> {
  console.log('Generating TypeScript fixtures for cross-compatibility testing\n');

  await generateCryptoVectors();
  await generateSecretBlobs();
  await generateHuffmanData();
  await generateStegoRoundtrip();

  console.log('\nAll TypeScript fixtures generated successfully!');
  console.log(`Fixtures directory: ${FIXTURES_DIR}`);
}

main().catch(console.error);
