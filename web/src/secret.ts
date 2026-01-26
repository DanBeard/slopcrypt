/**
 * Secret blob management.
 * Port of stego_secret.py lines 61-250.
 */

import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import pako from 'pako';
import {
  type Secret,
  SALT_SIZE,
  NONCE_SIZE,
  PAYLOAD_KEY_SIZE,
  SECRET_VERSION,
} from './types.ts';
import {
  deriveKey,
  encryptAesGcm,
  decryptAesGcm,
  randomBytes,
  generateRandomKnock,
  bytesToBase64,
  base64ToBytes,
} from './crypto.ts';

/**
 * Validate secret dict has required fields and valid values.
 */
export function validateSecret(secret: Secret): void {
  const required: (keyof Secret)[] = ['version', 'knock', 'k', 'payload_key'];
  for (const field of required) {
    if (!(field in secret)) {
      throw new Error(`Missing required field: ${field}`);
    }
  }

  if (secret.version !== 1 && secret.version !== SECRET_VERSION) {
    throw new Error(`Unsupported secret version: ${secret.version}`);
  }

  const k = secret.k;
  if (typeof k !== 'number' || k < 2 || (k & (k - 1)) !== 0) {
    throw new Error(`K must be a power of 2 >= 2, got ${k}`);
  }

  const knock = secret.knock;
  if (!Array.isArray(knock) || knock.length < 1) {
    throw new Error('Knock sequence must be a non-empty list');
  }

  for (const idx of knock) {
    if (typeof idx !== 'number' || idx < 0 || idx >= k) {
      throw new Error(`Knock index ${idx} must be in [0, ${k})`);
    }
  }

  // Validate payload key
  const payloadKey = secret.payload_key;
  if (!(payloadKey instanceof Uint8Array) || payloadKey.length !== PAYLOAD_KEY_SIZE) {
    throw new Error(`payload_key must be ${PAYLOAD_KEY_SIZE} bytes`);
  }
}

/**
 * Encrypt secret dict and return base64-encoded blob.
 * Format: base64([salt:16][nonce:12][ciphertext+tag])
 *
 * The plaintext is optionally zlib-compressed if it reduces size.
 */
export async function encryptSecretBlob(
  secret: Secret,
  password: string
): Promise<string> {
  const salt = randomBytes(SALT_SIZE);
  const key = await deriveKey(password, salt);

  // msgpack encode the secret
  let plaintext = new Uint8Array(msgpackEncode(secret));

  // Try zlib compression, use if smaller
  const compressed = pako.deflate(plaintext, { level: 9 });
  if (compressed.length < plaintext.length) {
    plaintext = compressed;
  }

  // Encrypt with AES-GCM (returns nonce + ciphertext)
  const encrypted = await encryptAesGcm(plaintext, key);

  // Combine: salt + encrypted (which includes nonce)
  const blob = new Uint8Array(salt.length + encrypted.length);
  blob.set(salt);
  blob.set(encrypted, salt.length);

  return bytesToBase64(blob);
}

/**
 * Decrypt base64-encoded secret blob.
 *
 * Auto-detects zlib compression: zlib starts with 0x78, msgpack dicts start with 0x80-0x8f.
 */
export async function decryptSecretBlob(
  blobB64: string,
  password: string
): Promise<Secret> {
  let blob: Uint8Array;
  try {
    blob = base64ToBytes(blobB64);
  } catch {
    throw new Error('Invalid base64 encoding');
  }

  if (blob.length < SALT_SIZE + NONCE_SIZE + 16) {
    throw new Error('Secret blob too short');
  }

  const salt = blob.slice(0, SALT_SIZE);
  const encrypted = blob.slice(SALT_SIZE);

  const key = await deriveKey(password, salt);
  let plaintext = await decryptAesGcm(encrypted, key);

  // Auto-detect zlib compression: zlib starts with 0x78, msgpack dicts start with 0x80-0x8f
  if (plaintext.length > 0 && plaintext[0] === 0x78) {
    try {
      plaintext = pako.inflate(plaintext);
    } catch {
      // Not actually zlib, use as-is
    }
  }

  const secret = msgpackDecode(plaintext) as Secret;

  // Convert payload_key from Buffer/Array to Uint8Array if needed
  if (secret.payload_key && !(secret.payload_key instanceof Uint8Array)) {
    secret.payload_key = new Uint8Array(secret.payload_key as unknown as ArrayLike<number>);
  }

  validateSecret(secret);
  return secret;
}

/**
 * Generate a new secret.
 */
export function generateSecret(options: {
  k: number;
  knock?: number[];
  preambleTokens?: number;
  suffixTokens?: number;
  temperature?: number;
  entropyThreshold?: number;
  huffmanSample?: Uint8Array;
  systemPrompt?: string;
  notes?: string;
}): Secret {
  const {
    k,
    knock = generateRandomKnock(k, 6),
    preambleTokens = 4,
    suffixTokens = 2,
    temperature = 0.8,
    entropyThreshold = 0.0,
    systemPrompt = '',
    notes = '',
  } = options;

  // Validate k is power of 2
  if (k < 2 || (k & (k - 1)) !== 0) {
    throw new Error(`K must be a power of 2 >= 2, got ${k}`);
  }

  // Build Huffman frequency table (null means use defaults)
  let huffmanFreq: Record<number, number> | null;
  if (options.huffmanSample) {
    huffmanFreq = buildFrequencyTableFromSample(options.huffmanSample);
  } else {
    huffmanFreq = null; // Store null to use defaults, saves ~230 bytes
  }

  // Generate random payload encryption key
  const payloadKey = randomBytes(PAYLOAD_KEY_SIZE);

  const secret: Secret = {
    version: SECRET_VERSION,
    knock,
    k,
    payload_key: payloadKey,
    preamble_tokens: preambleTokens,
    suffix_tokens: suffixTokens,
    temperature,
    entropy_threshold: entropyThreshold,
    huffman_freq: huffmanFreq,
    system_prompt: systemPrompt,
    notes,
  };

  validateSecret(secret);
  return secret;
}

/**
 * Build frequency table from sample text.
 */
function buildFrequencyTableFromSample(sample: Uint8Array): Record<number, number> {
  const freq: Record<number, number> = {};
  for (const byte of sample) {
    freq[byte] = (freq[byte] || 0) + 1;
  }

  // Ensure all printable ASCII have at least frequency 1
  for (let i = 32; i < 127; i++) {
    if (!(i in freq)) {
      freq[i] = 1;
    }
  }

  // Add newline and tab
  for (const i of [9, 10, 13]) {
    if (!(i in freq)) {
      freq[i] = 1;
    }
  }

  return freq;
}
