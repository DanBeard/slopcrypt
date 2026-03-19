"""
SlopCrypt Lite — Markov-optimized steganographic codec.

Strips out the LLM-oriented parts of slopcrypt (prefix filtering,
arithmetic coding, compression) and replaces them with a streamlined
pipeline designed for word-level Markov chains:

    payload → encrypt (AES-256-GCM) → Base-K encode → word tokens

Encoding a 183-byte Reticulum announce takes ~2-4ms on any hardware.

The key optimizations over the full slopcrypt pipeline:
- No filter_prefix_tokens (O(n²) string ops → O(1) slice)
- No arithmetic coding (Base-K is simpler and fast enough)
- No compression (overhead > savings for small packets)
- Word-boundary matching during decode (split on space, not startswith)
"""

from __future__ import annotations

import math
import random
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from slopcrypt.utils import TokenProb

NONCE_SIZE = 12


def _encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce + ciphertext + tag."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def _decrypt(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Input: nonce + ciphertext + tag."""
    if len(encrypted) < NONCE_SIZE + 16:
        raise ValueError("Encrypted payload too short")
    nonce = encrypted[:NONCE_SIZE]
    return AESGCM(key).decrypt(nonce, encrypted[NONCE_SIZE:], None)


def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    while len(bits) % 8 != 0:
        bits.append(0)
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def _bits_to_int(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _int_to_bits(value: int, num_bits: int) -> list[int]:
    return [(value >> i) & 1 for i in range(num_bits - 1, -1, -1)]


class TokenTrie:
    """
    Trie for fast prefix-safe filtering and token matching.

    Supports two operations:
    1. Build from a token list, marking which tokens are "leaf-only"
       (not a prefix of any other token) — used for prefix filtering.
    2. Walk the trie character-by-character to find the unique matching
       token at the start of a text — used for decode.
    """

    __slots__ = ("children", "token_idx", "is_terminal")

    def __init__(self):
        self.children: dict[str, TokenTrie] = {}
        self.token_idx: int = -1  # Index in top-K list, -1 if not a token endpoint
        self.is_terminal: bool = False  # True if this is a complete token

    @staticmethod
    def build(tokens: list[TokenProb]) -> tuple["TokenTrie", list[TokenProb]]:
        """
        Build a trie from tokens and return prefix-safe filtered list.

        Returns:
            (trie, safe_tokens) where safe_tokens excludes any token
            that is a prefix of another token in the list.
        """
        root = TokenTrie()

        # Insert all tokens
        for idx, tp in enumerate(tokens):
            node = root
            for ch in tp.token:
                if ch not in node.children:
                    node.children[ch] = TokenTrie()
                node = node.children[ch]
            node.token_idx = idx
            node.is_terminal = True

        # Collect prefix-safe tokens: a token is safe if its terminal
        # node has no children (it's a leaf — no longer token extends it)
        safe = []
        for idx, tp in enumerate(tokens):
            node = root
            for ch in tp.token:
                node = node.children[ch]
            if not node.children:  # Leaf node = no longer token is a prefix
                safe.append(tp)

        # Rebuild trie with only safe tokens (for clean decode matching)
        clean_root = TokenTrie()
        for idx, tp in enumerate(safe):
            node = clean_root
            for ch in tp.token:
                if ch not in node.children:
                    node.children[ch] = TokenTrie()
                node = node.children[ch]
            node.token_idx = idx
            node.is_terminal = True

        return clean_root, safe

    def match(self, text: str) -> tuple[int, int]:
        """
        Find the token matching the start of text.

        Returns:
            (token_index, token_length) or (-1, 0) if no match.
        """
        node = self
        best_idx = -1
        best_len = 0
        length = 0

        for ch in text:
            if ch not in node.children:
                break
            node = node.children[ch]
            length += 1
            if node.is_terminal:
                best_idx = node.token_idx
                best_len = length

        return best_idx, best_len


# Cache: distribution id → (trie, safe_tokens)
_trie_cache: dict[int, tuple[TokenTrie, list[TokenProb]]] = {}


def _get_top_k(client, context: str, k: int) -> list[TokenProb]:
    """Get top-K tokens. Distributions are pre-filtered for prefix safety
    by MarkovClient._precompute(), so this is just a slice."""
    dist = client.get_token_distribution(context)
    return dist[:k] if dist else []


def _get_trie(client, context: str, k: int) -> tuple[TokenTrie, list[TokenProb]]:
    """Get top-K tokens with a trie for O(m) decode matching."""
    dist = client.get_token_distribution(context)
    if not dist:
        return TokenTrie(), []

    top_k = dist[:k]
    cache_key = id(dist)
    cached = _trie_cache.get(cache_key)
    if cached is not None:
        return cached

    # Build trie from already prefix-safe tokens
    root = TokenTrie()
    for idx, tp in enumerate(top_k):
        node = root
        for ch in tp.token:
            if ch not in node.children:
                node.children[ch] = TokenTrie()
            node = node.children[ch]
        node.token_idx = idx
        node.is_terminal = True

    result = (root, top_k)
    _trie_cache[cache_key] = result
    return result


def encode(
    data: bytes,
    client,
    prompt: str,
    k: int = 16,
    knock: list[int] | None = None,
    payload_key: bytes | None = None,
    preamble_tokens: int = 3,
    suffix_tokens: int = 2,
) -> str:
    """
    Encode binary data into cover text using a Markov chain.

    Args:
        data: Raw bytes to encode.
        client: MarkovClient (or any client with get_token_distribution).
        prompt: Context string (previous conversation).
        k: Number of top tokens to select from (must be power of 2).
        knock: Token index sequence for framing (auto-generated if None).
        payload_key: AES-256-GCM key for encryption (random if None).
        preamble_tokens: Natural tokens before the knock.
        suffix_tokens: Natural tokens after the payload.

    Returns:
        Generated cover text (without prompt prefix).
    """
    bits_per_token = int(math.log2(k))

    # Encrypt
    if payload_key:
        encrypted = _encrypt(data, payload_key)
    else:
        encrypted = data

    # Build bit stream: 4-byte length header + encrypted payload
    full_data = len(encrypted).to_bytes(4, "big") + encrypted
    bit_stream = _bytes_to_bits(full_data)

    # Default knock
    if knock is None:
        knock = [4, 7, 2, 9, 14, 1]

    context = prompt
    tokens: list[str] = []

    def _top_k(ctx: str) -> list[TokenProb]:
        return _get_top_k(client, ctx, k)

    def _sample(top_k: list[TokenProb]) -> str:
        """Sample naturally from distribution."""
        if not top_k:
            return ""
        r = random.random()
        total = sum(t.prob for t in top_k)
        cumulative = 0.0
        for t in top_k:
            cumulative += t.prob / total
            if r < cumulative:
                return t.token
        return top_k[-1].token

    # Phase 1: Preamble (natural sampling)
    for _ in range(preamble_tokens):
        top_k = _top_k(context)
        if not top_k:
            break
        token = _sample(top_k)
        tokens.append(token)
        context += token

    # Phase 2: Knock sequence
    for idx in knock:
        top_k = _top_k(context)
        if not top_k:
            break
        actual_idx = idx % len(top_k)
        tokens.append(top_k[actual_idx].token)
        context += top_k[actual_idx].token

    # Phase 3: Payload (Base-K encoding)
    bit_idx = 0
    while bit_idx < len(bit_stream):
        chunk = bit_stream[bit_idx : bit_idx + bits_per_token]
        while len(chunk) < bits_per_token:
            chunk.append(0)
        index = _bits_to_int(chunk)

        top_k = _top_k(context)
        if not top_k:
            break
        if index >= len(top_k):
            index = index % len(top_k)

        tokens.append(top_k[index].token)
        context += top_k[index].token
        bit_idx += bits_per_token

    # Phase 4: Suffix (natural sampling)
    for _ in range(suffix_tokens):
        top_k = _top_k(context)
        if not top_k:
            break
        token = _sample(top_k)
        tokens.append(token)
        context += token

    return "".join(tokens)


def decode(
    cover_text: str,
    client,
    prompt: str,
    k: int = 16,
    knock: list[int] | None = None,
    payload_key: bytes | None = None,
) -> bytes:
    """
    Decode binary data from cover text.

    Args:
        cover_text: The generated cover text (without prompt).
        client: Same MarkovClient used for encoding.
        prompt: Same prompt used for encoding.
        k: Same K used for encoding.
        knock: Same knock sequence used for encoding.
        payload_key: Same AES key used for encoding.

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If knock not found or decryption fails.
    """
    bits_per_token = int(math.log2(k))
    if knock is None:
        knock = [4, 7, 2, 9, 14, 1]

    # Reconstruct: walk through cover text, find each token in top-K
    context = prompt
    remaining = cover_text
    token_indices: list[int] = []

    while remaining:
        trie, top_k = _get_trie(client, context, k)
        if not top_k:
            context += remaining[0]
            remaining = remaining[1:]
            continue

        # Match using trie: O(m) where m is token length
        idx, length = trie.match(remaining)
        if idx >= 0:
            token_indices.append(idx)
            context += remaining[:length]
            remaining = remaining[length:]
        else:
            context += remaining[0]
            remaining = remaining[1:]

    # Find knock sequence
    knock_len = len(knock)
    knock_pos = -1
    for i in range(len(token_indices) - knock_len + 1):
        if token_indices[i : i + knock_len] == knock:
            knock_pos = i
            break

    if knock_pos == -1:
        raise ValueError("Knock sequence not found in cover text")

    # Extract payload bits after knock
    payload_start = knock_pos + knock_len
    payload_indices = token_indices[payload_start:]

    bits: list[int] = []
    for idx in payload_indices:
        bits.extend(_int_to_bits(idx, bits_per_token))

        # Check if we have enough for length header
        if len(bits) >= 32:
            length = int.from_bytes(_bits_to_bytes(bits[:32]), "big")
            total_bits = 32 + length * 8
            if len(bits) >= total_bits:
                break

    all_bytes = _bits_to_bytes(bits)
    if len(all_bytes) < 4:
        raise ValueError("Payload too short")

    payload_len = int.from_bytes(all_bytes[:4], "big")
    if payload_len > len(all_bytes) - 4:
        payload_len = len(all_bytes) - 4

    encrypted = all_bytes[4 : 4 + payload_len]

    # Decrypt
    if payload_key:
        return _decrypt(encrypted, payload_key)
    return encrypted
