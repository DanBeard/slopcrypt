/**
 * Cryptographic utilities using Web Crypto API.
 * Port of stego_secret.py lines 43-181.
 */

import {
  PBKDF2_ITERATIONS,
  NONCE_SIZE,
  PAYLOAD_KEY_SIZE,
} from './types.ts';

/**
 * Derive 256-bit key from password using PBKDF2-SHA256.
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive raw key bytes from password using PBKDF2-SHA256.
 * Used for testing cross-compatibility with Python.
 */
export async function deriveKeyBytes(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    256 // 32 bytes = 256 bits
  );

  return new Uint8Array(keyBits);
}

/**
 * Encrypt data with AES-256-GCM.
 * @returns [nonce:12][ciphertext+tag]
 */
export async function encryptAesGcm(
  plaintext: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    plaintext as BufferSource
  );

  // Combine nonce + ciphertext
  const result = new Uint8Array(nonce.length + ciphertext.byteLength);
  result.set(nonce);
  result.set(new Uint8Array(ciphertext), nonce.length);

  return result;
}

/**
 * Decrypt data with AES-256-GCM.
 * @param encrypted [nonce:12][ciphertext+tag]
 */
export async function decryptAesGcm(
  encrypted: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  if (encrypted.length < NONCE_SIZE + 16) {
    throw new Error('Encrypted data too short');
  }

  const nonce = encrypted.slice(0, NONCE_SIZE);
  const ciphertext = encrypted.slice(NONCE_SIZE);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error('Decryption failed - wrong password or corrupted data');
  }
}

/**
 * Encrypt payload data with AES-256-GCM using raw key bytes.
 * @returns [nonce:12][ciphertext+tag]
 */
export async function encryptPayload(
  data: Uint8Array,
  keyBytes: Uint8Array
): Promise<Uint8Array> {
  if (keyBytes.length !== PAYLOAD_KEY_SIZE) {
    throw new Error(`Key must be ${PAYLOAD_KEY_SIZE} bytes`);
  }

  const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ]);

  return encryptAesGcm(data, key);
}

/**
 * Decrypt payload data with AES-256-GCM using raw key bytes.
 * @param encrypted [nonce:12][ciphertext+tag]
 */
export async function decryptPayload(
  encrypted: Uint8Array,
  keyBytes: Uint8Array
): Promise<Uint8Array> {
  if (keyBytes.length !== PAYLOAD_KEY_SIZE) {
    throw new Error(`Key must be ${PAYLOAD_KEY_SIZE} bytes`);
  }

  const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, [
    'decrypt',
  ]);

  try {
    return await decryptAesGcm(encrypted, key);
  } catch {
    throw new Error('Payload decryption failed - corrupted data or wrong key');
  }
}

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate random knock sequence with values in [0, k).
 */
export function generateRandomKnock(k: number, length: number = 6): number[] {
  const result: number[] = [];
  const bytes = randomBytes(length * 2); // Extra bytes for rejection sampling
  let idx = 0;

  while (result.length < length && idx < bytes.length) {
    // Simple modulo - slightly biased but acceptable for knock sequences
    const value = bytes[idx] % k;
    result.push(value);
    idx++;
  }

  // Fallback if we ran out of bytes (shouldn't happen)
  while (result.length < length) {
    result.push(Math.floor(Math.random() * k));
  }

  return result;
}

/**
 * Encode bytes to base64 string.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Decode base64 string to bytes.
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
