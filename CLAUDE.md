# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LLM steganography tool that hides binary data in LLM-generated text using Base-K encoding. Each token encodes `log2(K)` bits by selecting from the top-K most probable tokens. Includes encrypted secret management, Huffman compression, and payload encryption.

## Commands

```bash
# Run all tests
python -m pytest test_stego_secret.py test_stego.py -v

# Run specific test class
python -m pytest test_stego_secret.py -v -k TestCrypto

# Quick roundtrip with stego_secret.py (recommended)
python stego_secret.py generate-secret -o test.secret --password test123
echo "Secret message" | python stego_secret.py encode --secret test.secret --mock --password test123 \
  | python stego_secret.py decode --secret test.secret --mock --password test123

# Low-level roundtrip with stego_basek.py (for debugging)
echo "test" | python stego_basek.py encode --mock --knock 4,7,2,9 --preamble 10 --suffix 10 \
  | python stego_basek.py decode --mock --knock 4,7,2,9
```

## Architecture

**High-level wrapper** (`stego_secret.py`):
- Encrypted secret blob with password-derived key (PBKDF2 + AES-256-GCM)
- Payload encryption (defeats frequency analysis)
- Huffman compression (~4-4.5 bits/char for English)
- CLI: `generate-secret`, `encode`, `decode`, `show-secret`

**Secret blob structure** (v2):
```python
{
    'version': 2,
    'knock': [4, 7, 2, 9, 14, 1],  # Auto-generated or explicit
    'k': 16,
    'payload_key': <32 bytes>,     # AES-256 key for payload encryption
    'preamble_tokens': 10,
    'suffix_tokens': 10,
    'temperature': 0.8,
    'huffman_freq': {...},         # Byte frequencies for compression
    'notes': '',
}
```

**Encoding flow**:
```
Message → Huffman compress → AES-256-GCM encrypt → Base-K encode
Prompt → [Preamble tokens] → [Knock sequence] → [Length + Encrypted payload] → [Suffix tokens]
```

**Key modules:**
- `stego_secret.py` - Main user-facing wrapper with encryption, compression, and CLI
- `stego_basek.py` - Low-level encode/decode logic: `encode_with_knock()`, `decode_with_knock()`
- `utils.py` - Bit conversion, token filtering (`filter_prefix_tokens`), knock utilities
- `lm_client.py` - LLM backends: `MockLMClient`, `LlamaCppClient`, `LMClient` (LM Studio)

**Critical invariants:**
- Encoder and decoder must use identical: model, K value, secret (knock, payload_key)
- K must be power of 2 (maps cleanly to bits)
- `filter_prefix_tokens()` removes ambiguous prefix tokens for deterministic decoding
- Token sorting is stable (by -prob, then token string) to ensure consistency

## Dependencies

```bash
pip install msgpack cryptography httpx llama-cpp-python pytest
```

## Research Context

This is exploratory research at the intersection of LLMs and steganography. Approach with intellectual honesty—challenge assumptions, document failures, and iterate based on evidence rather than assumptions.
