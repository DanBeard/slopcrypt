/**
 * Huffman compression for payload encoding.
 * Port of stego_secret.py lines 253-525.
 */

import {
  COMPRESSION_NONE,
  COMPRESSION_HUFFMAN,
  COMPRESSION_ARITHMETIC,
} from './types.ts';

/**
 * Default English byte frequencies (based on typical text).
 */
export const DEFAULT_FREQUENCIES: Record<number, number> = {
  32: 18000, // space
  101: 12000, // e
  116: 9000, // t
  97: 8000, // a
  111: 7500, // o
  105: 7000, // i
  110: 6700, // n
  115: 6300, // s
  104: 6000, // h
  114: 5900, // r
  100: 4200, // d
  108: 4000, // l
  99: 2700, // c
  117: 2700, // u
  109: 2400, // m
  119: 2300, // w
  102: 2200, // f
  103: 2000, // g
  121: 1900, // y
  112: 1900, // p
  98: 1500, // b
  118: 1000, // v
  107: 800, // k
  106: 150, // j
  120: 150, // x
  113: 100, // q
  122: 70, // z
  // Uppercase
  84: 800, // T
  73: 700, // I
  65: 600, // A
  83: 500, // S
  72: 400, // H
  87: 350, // W
  67: 300, // C
  66: 250, // B
  80: 200, // P
  77: 200, // M
  70: 180, // F
  68: 170, // D
  82: 160, // R
  76: 150, // L
  78: 140, // N
  69: 130, // E
  71: 120, // G
  79: 110, // O
  85: 100, // U
  86: 90, // V
  89: 80, // Y
  75: 70, // K
  74: 60, // J
  88: 50, // X
  81: 40, // Q
  90: 30, // Z
  // Punctuation and digits
  46: 600, // .
  44: 500, // ,
  39: 200, // '
  34: 150, // "
  33: 100, // !
  63: 100, // ?
  45: 80, // -
  58: 60, // :
  59: 50, // ;
  40: 40, // (
  41: 40, // )
  48: 50, // 0
  49: 50, // 1
  50: 40, // 2
  51: 35, // 3
  52: 30, // 4
  53: 30, // 5
  54: 25, // 6
  55: 25, // 7
  56: 20, // 8
  57: 20, // 9
  10: 300, // newline
};

/**
 * Huffman tree node.
 */
interface HuffmanNode {
  freq: number;
  byte: number | null; // null for internal nodes
  left: HuffmanNode | null;
  right: HuffmanNode | null;
  seq?: number; // Sequence number for tie-breaking
}

/**
 * Priority queue using a simple sorted array with deterministic tie-breaking.
 *
 * When frequencies are equal, we need consistent ordering to match Python's heapq.
 * We use a sequence number to maintain insertion order for tie-breaking.
 */
class PriorityQueue {
  private items: HuffmanNode[] = [];
  private seqCounter = 0;

  push(node: HuffmanNode): void {
    node.seq = this.seqCounter++;
    this.items.push(node);
    // Sort by frequency, then by sequence number for stable ordering
    this.items.sort((a, b) => {
      if (a.freq !== b.freq) return a.freq - b.freq;
      return (a.seq ?? 0) - (b.seq ?? 0);
    });
  }

  pop(): HuffmanNode | undefined {
    return this.items.shift();
  }

  get length(): number {
    return this.items.length;
  }
}

/**
 * Build Huffman tree from byte frequencies.
 *
 * To match Python's behavior, we need to:
 * 1. Process entries in sorted order (by byte value) for deterministic leaf creation
 * 2. Use stable tie-breaking in the priority queue
 */
function buildHuffmanTree(frequencies: Record<number, number>): HuffmanNode | null {
  const entries = Object.entries(frequencies);
  if (entries.length === 0) return null;

  const pq = new PriorityQueue();

  // Create leaf nodes - sort by byte value first for deterministic ordering
  // This matches Python's heapq behavior where items are added in consistent order
  const sortedEntries = entries
    .map(([byteStr, freq]) => ({ byte: parseInt(byteStr), freq }))
    .sort((a, b) => a.byte - b.byte);

  for (const { byte, freq } of sortedEntries) {
    pq.push({ freq, byte, left: null, right: null });
  }

  // Build tree
  while (pq.length > 1) {
    const left = pq.pop()!;
    const right = pq.pop()!;
    const internal: HuffmanNode = {
      freq: left.freq + right.freq,
      byte: null,
      left,
      right,
    };
    pq.push(internal);
  }

  return pq.pop() ?? null;
}

/**
 * Recursively build Huffman codes from tree.
 */
function buildCodes(
  node: HuffmanNode | null,
  prefix: string,
  codes: Map<number, string>
): void {
  if (node === null) return;

  if (node.byte !== null) {
    // Leaf node
    codes.set(node.byte, prefix || '0'); // Single node case
  } else {
    buildCodes(node.left, prefix + '0', codes);
    buildCodes(node.right, prefix + '1', codes);
  }
}

/**
 * Get Huffman codes for each byte.
 */
function getHuffmanCodes(frequencies: Record<number, number>): Map<number, string> {
  const tree = buildHuffmanTree(frequencies);
  const codes = new Map<number, string>();
  buildCodes(tree, '', codes);
  return codes;
}

/**
 * Encode data using Huffman coding.
 * @returns Encoded bytes: [bit_count:4][huffman_bits padded to bytes]
 */
export function huffmanEncode(
  data: Uint8Array,
  frequencies: Record<number, number>
): Uint8Array {
  const codes = getHuffmanCodes(frequencies);

  // Build bit array
  const bits: number[] = [];
  for (const byte of data) {
    const code = codes.get(byte);
    if (code !== undefined) {
      for (const c of code) {
        bits.push(parseInt(c));
      }
    } else {
      // Fallback: use 8-bit literal with escape (255 followed by byte)
      const escapeCode = codes.get(255);
      if (escapeCode !== undefined) {
        for (const c of escapeCode) {
          bits.push(parseInt(c));
        }
      }
      for (let i = 7; i >= 0; i--) {
        bits.push((byte >> i) & 1);
      }
    }
  }

  // Store bit count (4 bytes) + padded bits
  const bitCount = bits.length;

  // Pad to byte boundary
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  // Convert to bytes
  const result = new Uint8Array(4 + bits.length / 8);

  // Write bit count as big-endian 32-bit
  result[0] = (bitCount >> 24) & 0xff;
  result[1] = (bitCount >> 16) & 0xff;
  result[2] = (bitCount >> 8) & 0xff;
  result[3] = bitCount & 0xff;

  // Write bits as bytes
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i + j];
    }
    result[4 + i / 8] = byte;
  }

  return result;
}

/**
 * Decode Huffman-encoded data.
 * @param encoded [bit_count:4][huffman_bits]
 */
export function huffmanDecode(
  encoded: Uint8Array,
  frequencies: Record<number, number>
): Uint8Array {
  if (encoded.length < 4) {
    throw new Error('Encoded data too short');
  }

  const bitCount =
    (encoded[0] << 24) | (encoded[1] << 16) | (encoded[2] << 8) | encoded[3];
  const dataBytes = encoded.slice(4);

  // Convert bytes to bits
  const bits: number[] = [];
  for (const byte of dataBytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  // Trim padding
  bits.length = Math.min(bits.length, bitCount);

  // Build decode tree
  const tree = buildHuffmanTree(frequencies);
  if (tree === null) return new Uint8Array(0);

  // Decode
  const result: number[] = [];
  let node = tree;
  let i = 0;

  while (i < bits.length) {
    const bit = bits[i];
    i++;

    if (bit === 0) {
      node = node.left!;
    } else {
      node = node.right!;
    }

    if (node === null) {
      throw new Error('Invalid Huffman data');
    }

    if (node.byte !== null) {
      result.push(node.byte);
      node = tree;
    }
  }

  return new Uint8Array(result);
}

// ============================================================================
// Arithmetic Coding (better compression than Huffman)
// ============================================================================

// Constants for 32-bit arithmetic coding
// Using 32-bit precision ensures cross-language compatibility (Python, TypeScript)
// Note: Use explicit values since JS bitwise ops only work on 32-bit integers
// Full range would be 0x100000000 (2^32) but we use MASK for bounds
const ARITH_NUM_BITS = 32;
const ARITH_HALF = 0x80000000; // 2^31 (can't use >>> on values >= 2^32)
const ARITH_QUARTER = 0x40000000; // 2^30
const ARITH_MASK = 0xffffffff; // 2^32 - 1

/**
 * Build cumulative frequency model for arithmetic coding.
 * Sorting by byte value ensures deterministic behavior across Python/TypeScript.
 */
function buildArithmeticModel(
  frequencies: Record<number, number>
): { symbols: number[]; cumulative: number[]; total: number } {
  // Sort by byte value for deterministic cross-language ordering
  const sortedEntries = Object.entries(frequencies)
    .map(([byteStr, freq]) => ({ byte: parseInt(byteStr), freq }))
    .sort((a, b) => a.byte - b.byte);

  const symbols = sortedEntries.map((e) => e.byte);
  const freqs = sortedEntries.map((e) => e.freq);

  // Build cumulative frequencies: [0, f0, f0+f1, f0+f1+f2, ...]
  const cumulative = [0];
  for (const f of freqs) {
    cumulative.push(cumulative[cumulative.length - 1] + f);
  }

  return { symbols, cumulative, total: cumulative[cumulative.length - 1] };
}

/**
 * Range-based arithmetic encoder using 32-bit integer math.
 */
class ArithmeticEncoder {
  private symbols: number[];
  private cumulative: number[];
  private total: number;
  private symbolToIdx: Map<number, number>;

  private low: number = 0;
  private high: number = ARITH_MASK;
  private pendingBits: number = 0;
  private outputBits: number[] = [];

  constructor(frequencies: Record<number, number>) {
    const model = buildArithmeticModel(frequencies);
    this.symbols = model.symbols;
    this.cumulative = model.cumulative;
    this.total = model.total;

    this.symbolToIdx = new Map();
    for (let i = 0; i < this.symbols.length; i++) {
      this.symbolToIdx.set(this.symbols[i], i);
    }
  }

  private emitBit(bit: number): void {
    this.outputBits.push(bit);
    // Emit pending bits (opposite of emitted bit)
    const opposite = 1 - bit;
    for (let i = 0; i < this.pendingBits; i++) {
      this.outputBits.push(opposite);
    }
    this.pendingBits = 0;
  }

  private renormalize(): void {
    while (true) {
      if (this.high < ARITH_HALF) {
        // Both low and high in lower half [0, 0.5)
        this.emitBit(0);
        this.low = (this.low << 1) >>> 0;
        this.high = ((this.high << 1) | 1) >>> 0;
      } else if (this.low >= ARITH_HALF) {
        // Both low and high in upper half [0.5, 1)
        this.emitBit(1);
        this.low = ((this.low - ARITH_HALF) << 1) >>> 0;
        this.high = (((this.high - ARITH_HALF) << 1) | 1) >>> 0;
      } else if (this.low >= ARITH_QUARTER && this.high < 3 * ARITH_QUARTER) {
        // Range straddles midpoint [0.25, 0.75)
        this.pendingBits++;
        this.low = ((this.low - ARITH_QUARTER) << 1) >>> 0;
        this.high = (((this.high - ARITH_QUARTER) << 1) | 1) >>> 0;
      } else {
        break;
      }
    }
  }

  encodeSymbol(byte: number): void {
    const idx = this.symbolToIdx.get(byte);
    if (idx === undefined) {
      throw new Error(`Symbol ${byte} not in frequency table`);
    }

    const rangeSize = this.high - this.low + 1;

    // Narrow the range based on cumulative frequencies
    const cumLow = this.cumulative[idx];
    const cumHigh = this.cumulative[idx + 1];

    // Integer division - use Math.floor for consistent behavior
    this.high =
      (this.low + Math.floor((rangeSize * cumHigh) / this.total) - 1) >>> 0;
    this.low = (this.low + Math.floor((rangeSize * cumLow) / this.total)) >>> 0;

    this.renormalize();
  }

  finish(): Uint8Array {
    // Flush remaining bits to uniquely identify the final range
    this.pendingBits++;
    if (this.low < ARITH_QUARTER) {
      this.emitBit(0);
    } else {
      this.emitBit(1);
    }

    // Pad to byte boundary
    while (this.outputBits.length % 8 !== 0) {
      this.outputBits.push(0);
    }

    // Convert bits to bytes
    const result = new Uint8Array(this.outputBits.length / 8);
    for (let i = 0; i < this.outputBits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) {
        byte = (byte << 1) | this.outputBits[i + j];
      }
      result[i / 8] = byte;
    }

    return result;
  }
}

/**
 * Range-based arithmetic decoder using 32-bit integer math.
 */
class ArithmeticDecoder {
  private symbols: number[];
  private cumulative: number[];
  private total: number;
  private bits: number[];
  private bitIndex: number = 0;

  private low: number = 0;
  private high: number = ARITH_MASK;
  private value: number = 0;

  constructor(frequencies: Record<number, number>, encodedBits: number[]) {
    const model = buildArithmeticModel(frequencies);
    this.symbols = model.symbols;
    this.cumulative = model.cumulative;
    this.total = model.total;
    this.bits = encodedBits;

    // Initialize value from first 32 bits
    for (let i = 0; i < ARITH_NUM_BITS; i++) {
      this.value = ((this.value << 1) | this.readBit()) >>> 0;
    }
  }

  private readBit(): number {
    if (this.bitIndex < this.bits.length) {
      return this.bits[this.bitIndex++];
    }
    return 0;
  }

  private renormalize(): void {
    while (true) {
      if (this.high < ARITH_HALF) {
        // Both in lower half
        this.low = (this.low << 1) >>> 0;
        this.high = ((this.high << 1) | 1) >>> 0;
        this.value = ((this.value << 1) | this.readBit()) >>> 0;
      } else if (this.low >= ARITH_HALF) {
        // Both in upper half
        this.low = ((this.low - ARITH_HALF) << 1) >>> 0;
        this.high = (((this.high - ARITH_HALF) << 1) | 1) >>> 0;
        this.value = (((this.value - ARITH_HALF) << 1) | this.readBit()) >>> 0;
      } else if (this.low >= ARITH_QUARTER && this.high < 3 * ARITH_QUARTER) {
        // Range straddles midpoint
        this.low = ((this.low - ARITH_QUARTER) << 1) >>> 0;
        this.high = (((this.high - ARITH_QUARTER) << 1) | 1) >>> 0;
        this.value =
          (((this.value - ARITH_QUARTER) << 1) | this.readBit()) >>> 0;
      } else {
        break;
      }
    }
  }

  decodeSymbol(): number {
    const rangeSize = this.high - this.low + 1;

    // Find which symbol the current value corresponds to
    const scaledValue = Math.floor(
      ((this.value - this.low + 1) * this.total - 1) / rangeSize
    );

    // Binary search for the symbol
    let lo = 0;
    let hi = this.symbols.length;
    while (lo < hi) {
      const mid = Math.floor((lo + hi + 1) / 2);
      if (this.cumulative[mid] <= scaledValue) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    const idx = lo;

    // Update range (same as encoder)
    const cumLow = this.cumulative[idx];
    const cumHigh = this.cumulative[idx + 1];

    this.high =
      (this.low + Math.floor((rangeSize * cumHigh) / this.total) - 1) >>> 0;
    this.low = (this.low + Math.floor((rangeSize * cumLow) / this.total)) >>> 0;

    this.renormalize();

    return this.symbols[idx];
  }
}

/**
 * Encode data using arithmetic coding.
 * @returns Encoded bytes: [original_length:4][encoded_data]
 */
export function arithmeticEncode(
  data: Uint8Array,
  frequencies: Record<number, number>
): Uint8Array {
  if (data.length === 0) {
    return new Uint8Array([0, 0, 0, 0]);
  }

  const encoder = new ArithmeticEncoder(frequencies);

  for (const byte of data) {
    encoder.encodeSymbol(byte);
  }

  const encoded = encoder.finish();

  // Prepend original length (4 bytes, big-endian)
  const result = new Uint8Array(4 + encoded.length);
  result[0] = (data.length >> 24) & 0xff;
  result[1] = (data.length >> 16) & 0xff;
  result[2] = (data.length >> 8) & 0xff;
  result[3] = data.length & 0xff;
  result.set(encoded, 4);

  return result;
}

/**
 * Decode arithmetic-coded data.
 * @param encoded [original_length:4][encoded_data]
 */
export function arithmeticDecode(
  encoded: Uint8Array,
  frequencies: Record<number, number>
): Uint8Array {
  if (encoded.length < 4) {
    throw new Error('Encoded data too short');
  }

  const originalLength =
    (encoded[0] << 24) | (encoded[1] << 16) | (encoded[2] << 8) | encoded[3];
  if (originalLength === 0) {
    return new Uint8Array(0);
  }

  const dataBytes = encoded.slice(4);

  // Convert bytes to bits
  const bits: number[] = [];
  for (const byte of dataBytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }

  const decoder = new ArithmeticDecoder(frequencies, bits);

  const result = new Uint8Array(originalLength);
  for (let i = 0; i < originalLength; i++) {
    result[i] = decoder.decodeSymbol();
  }

  return result;
}

/**
 * Compress payload, choosing best method.
 *
 * Tries arithmetic coding first (best compression), then Huffman,
 * then falls back to raw if compression increases size.
 *
 * @returns Tuple of [compressed_data, compression_type]
 */
export function compressPayload(
  data: Uint8Array,
  frequencies: Record<number, number>
): [Uint8Array, number] {
  if (data.length === 0) {
    return [data, COMPRESSION_NONE];
  }

  const candidates: [Uint8Array, number][] = [[data, COMPRESSION_NONE]];

  // Try Huffman coding (handles unknown bytes via escape mechanism)
  const huffmanEncoded = huffmanEncode(data, frequencies);
  candidates.push([huffmanEncoded, COMPRESSION_HUFFMAN]);

  // Try arithmetic coding (typically 10-20% better than Huffman)
  // Only works if all bytes in data are in the frequency table
  const allBytesKnown = Array.from(data).every((byte) => byte in frequencies);
  if (allBytesKnown) {
    const arithEncoded = arithmeticEncode(data, frequencies);
    candidates.push([arithEncoded, COMPRESSION_ARITHMETIC]);
  }

  // Return smallest by byte length
  let best = candidates[0];
  for (const candidate of candidates) {
    if (candidate[0].length < best[0].length) {
      best = candidate;
    }
  }

  return best;
}

/**
 * Decompress payload based on compression type.
 */
export function decompressPayload(
  data: Uint8Array,
  compressionType: number,
  frequencies: Record<number, number>
): Uint8Array {
  if (compressionType === COMPRESSION_NONE) {
    return data;
  } else if (compressionType === COMPRESSION_HUFFMAN) {
    return huffmanDecode(data, frequencies);
  } else if (compressionType === COMPRESSION_ARITHMETIC) {
    return arithmeticDecode(data, frequencies);
  } else {
    throw new Error(`Unknown compression type: ${compressionType}`);
  }
}

/**
 * Build frequency table from sample text.
 */
export function buildFrequencyTable(sample: Uint8Array): Record<number, number> {
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
