/**
 * Bit manipulation utilities.
 * Port of utils.py lines 17-56.
 */

/**
 * Convert bytes to list of bits.
 */
export function bytesToBits(data: Uint8Array): number[] {
  const bits: number[] = [];
  for (const byte of data) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

/**
 * Convert list of bits to bytes.
 */
export function bitsToBytes(bits: number[]): Uint8Array {
  // Pad to multiple of 8
  const padded = [...bits];
  while (padded.length % 8 !== 0) {
    padded.push(0);
  }

  const result = new Uint8Array(padded.length / 8);
  for (let i = 0; i < padded.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | padded[i + j];
    }
    result[i / 8] = byte;
  }
  return result;
}

/**
 * Convert list of bits to integer.
 */
export function bitsToInt(bits: number[]): number {
  let value = 0;
  for (const bit of bits) {
    value = (value << 1) | bit;
  }
  return value;
}

/**
 * Convert integer to list of bits.
 */
export function intToBits(value: number, numBits: number): number[] {
  const bits: number[] = [];
  for (let i = numBits - 1; i >= 0; i--) {
    bits.push((value >> i) & 1);
  }
  return bits;
}
