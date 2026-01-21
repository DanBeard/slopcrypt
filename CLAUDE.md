# CLAUDE.md

Guidance for Claude Code when working in this repository.

## SlopCrypt

**Hide your data in slop!**

LLM steganography that embeds binary data in AI-generated text. Each token encodes `log2(K)` bits by picking from the top-K most probable tokens. Yes, we're weaponizing the slop. No, we're not sorry.

## Quick Reference

```bash
# Tests
python -m pytest tests/ -v

# Roundtrip (mock client)
python -m slopcrypt.secret generate-secret -o test.secret --password test123
echo "Secret" | python -m slopcrypt.secret encode --secret test.secret --mock --password test123 \
  | python -m slopcrypt.secret decode --secret test.secret --mock --password test123

# Low-level (debugging)
echo "test" | python -m slopcrypt.encode encode --mock --knock 4,7,2,9 --preamble 10 --suffix 10 \
  | python -m slopcrypt.encode decode --mock --knock 4,7,2,9
```

## Architecture

```
slopcrypt/                    # Main package
├── __init__.py               # Public API exports
├── secret.py                 # Secret management + message wrappers + CLI
├── compress.py               # Huffman + Arithmetic coding
├── encode.py                 # Base-K steganography
├── lm_client.py              # LLM client implementations
└── utils.py                  # Bit manipulation, token utilities
tests/
├── test_secret.py            # Tests for secret.py + compress.py
└── test_encode.py            # Tests for encode.py + utils.py
```

**`slopcrypt.secret`** — Main wrapper with the good stuff:
- PBKDF2 + AES-256-GCM encrypted secrets
- AES-256-GCM payload encryption (frequency analysis? never heard of her)

**`slopcrypt.compress`** — Compression algorithms:
- Huffman compression (~4-4.5 bits/char for English)
- Arithmetic coding (10-20% better than Huffman)

**`slopcrypt.encode`** — Low-level encode/decode, for when you want to suffer

**`slopcrypt.lm_client`** — LLM backends: `MockLMClient`, `LlamaCppClient`, `MLXClient`

**`slopcrypt.utils`** — Bit wrangling, token filtering, knock utilities

**Encoding flow:**
```
Message → Huffman compress → AES encrypt → Base-K encode into tokens
[Preamble] → [Knock sequence] → [Length + Encrypted payload] → [Suffix]
```

**Invariants:**
- Encoder/decoder need identical: model, K, secret (knock + payload_key)
- K must be power of 2
- Token sorting is stable (-prob, then token string)

## Setup

```bash
# Install dependencies
uv sync --all-extras

# Or just core + dev
uv sync --extra dev

# Run tests
uv run pytest

# Format/lint
uv run ruff check .
uv run ruff format .
```

## Research Philosophy

This is exploratory work at the intersection of LLMs and steganography. Challenge assumptions, document failures, iterate on evidence. Negative results are still results—document why things don't work before pivoting.

When in doubt: be direct, cite specifics, and don't dismiss ideas without technical rationale.
