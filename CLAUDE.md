# CLAUDE.md

Guidance for Claude Code when working in this repository.

## SlopCrypt

**Hide your data in slop!**

LLM steganography that embeds binary data in AI-generated text. Each token encodes `log2(K)` bits by picking from the top-K most probable tokens. Yes, we're weaponizing the slop. No, we're not sorry.

## Quick Reference

```bash
# Tests
python -m pytest test_stego_secret.py test_stego.py -v

# Roundtrip (mock client)
python stego_secret.py generate-secret -o test.secret --password test123
echo "Secret" | python stego_secret.py encode --secret test.secret --mock --password test123 \
  | python stego_secret.py decode --secret test.secret --mock --password test123

# Low-level (debugging)
echo "test" | python stego_basek.py encode --mock --knock 4,7,2,9 --preamble 10 --suffix 10 \
  | python stego_basek.py decode --mock --knock 4,7,2,9
```

## Architecture

**`stego_secret.py`** — Main wrapper with the good stuff:
- PBKDF2 + AES-256-GCM encrypted secrets
- AES-256-GCM payload encryption (frequency analysis? never heard of her)
- Huffman compression (~4-4.5 bits/char for English)

**`stego_basek.py`** — Low-level encode/decode, for when you want to suffer

**`lm_client.py`** — LLM backends: `MockLMClient`, `LlamaCppClient`, `LMClient`, `MLXClient`

**`utils.py`** — Bit wrangling, token filtering, knock utilities

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
