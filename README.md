# SlopCrypt

**Hide your data in slop!**

LLM steganography that embeds binary data in AI-generated text. Because if we're going to be drowning in AI slop anyway, we might as well make it useful.

## How it Works

Your secret message gets compressed, encrypted, and encoded into the token choices of an LLM. The output looks like regular AI-generated text (read: slop), but contains your hidden payload. The recipient uses the same model and shared secret to decode it.

Using arithmetic coding, each token encodes a variable number of bits based on the model's probability distribution. High-entropy contexts encode more bits; when the model is very confident about the next token, we can skip encoding entirely for more natural-sounding text. Not exactly blazing throughput, but hey—it's *plausibly deniable* throughput.

## Features

- **Encrypted secrets** — PBKDF2 + AES-256-GCM (we're not animals)
- **Payload encryption** — Defeats frequency analysis on your plaintext
- **Arithmetic compression** — Better than Huffman, ~10-20% smaller payloads
- **Entropy threshold** — Skip encoding on confident tokens for natural text
- **Knock sequence** — Find the payload without knowing the exact prompt
- **Multiple backends** — Mock client, local GGUF, MLX (Apple Silicon)

## Quickstart

```bash
# Install (using uv)
uv sync --all-extras

# Or with pip
pip install msgpack cryptography llama-cpp-python

# Generate a secret
uv run python -m slopcrypt.secret generate-secret -o my.secret --password hunter2

# Encode (mock client for testing)
echo "Meet at the usual place" | uv run python -m slopcrypt.secret encode \
  --secret my.secret --mock --password hunter2

# Roundtrip
echo "Hello World" | uv run python -m slopcrypt.secret encode --secret my.secret --mock --password hunter2 \
  | uv run python -m slopcrypt.secret decode --secret my.secret --mock --password hunter2
```

## Use with a Real Model

The mock client is for testing. For actual steganography, use a real LLM:

```bash
# Download a small model
wget https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf

# Encode
echo "Secret data" | uv run python -m slopcrypt.secret encode \
  --secret my.secret --model-path smollm2-135m-instruct-q8_0.gguf --password hunter2 -o cover.txt

# Decode
uv run python -m slopcrypt.secret decode --secret my.secret \
  --model-path smollm2-135m-instruct-q8_0.gguf --password hunter2 -i cover.txt
```

Or with MLX on Apple Silicon:

```bash
# Install MLX support
uv sync --extra mlx

# Encode
echo "Secret" | uv run python -m slopcrypt.secret encode --secret my.secret \
  --mlx --mlx-model mlx-community/Llama-3.2-1B-Instruct-4bit --password hunter2 -o cover.txt

# Decode
uv run python -m slopcrypt.secret decode --secret my.secret \
  --mlx --mlx-model mlx-community/Llama-3.2-1B-Instruct-4bit --password hunter2 -i cover.txt
```

## The Secret Blob

All the parameters live in an encrypted secret file:

```python
{
    'version': 2,
    'knock': [4, 7, 2, 9, 14, 1],  # Locates payload in the slop
    'k': 8,                         # Top-K tokens for selection
    'payload_key': <32 bytes>,      # AES key for payload
    'preamble_tokens': 4,           # Natural tokens before knock
    'suffix_tokens': 2,             # Natural tokens after payload
    'entropy_threshold': 0.9,       # Skip encoding if top prob > threshold
    'huffman_freq': {...},          # Compression frequencies (for fallback)
}
```

## Encoding Flow

```
Your message → Arithmetic compress → AES-256-GCM encrypt → Stego encode

Cover text structure:
[Prompt] → [Preamble] → [Knock sequence] → [Encrypted payload] → [Suffix]
            ~~~~~~~~     ~~~~~~~~~~~~~~     ~~~~~~~~~~~~~~~~~~    ~~~~~~
            (natural)    (locator)          (your data)           (natural)
```

## CLI Reference

```bash
# Generate secret
uv run python -m slopcrypt.secret generate-secret -o FILE --password PASS [--k K] [--entropy-threshold 0.9]

# Encode
uv run python -m slopcrypt.secret encode --secret FILE --password PASS [--model-path PATH | --mlx | --mock]

# Decode
uv run python -m slopcrypt.secret decode --secret FILE --password PASS [--model-path PATH | --mlx | --mock]

# Inspect secret (for debugging)
uv run python -m slopcrypt.secret show-secret --secret FILE --password PASS
```

## Development

```bash
# Run tests
uv run pytest

# Lint
uv run ruff check .

# Format
uv run ruff format .
```

## Security Notes

- Secret blob: AES-256-GCM with PBKDF2-derived key (600k iterations)
- Payload: separately encrypted with AES-256-GCM
- Compression happens *before* encryption (no frequency leaks)
- Keep your `.secret` file... secret

**⚠️ No Third-Party Review:** This is an experimental project that has not been audited by security professionals. The cryptographic primitives (AES-256-GCM, PBKDF2) are standard, but the overall system design hasn't been vetted. Don't rely on this if your life or liberty depends on it.

## Why "SlopCrypt"?

Because the cover text is LLM-generated slop. We're not hiding data in Shakespeare—we're hiding it in "The sun set over the horizon, painting the sky in hues of orange and pink, as Sarah contemplated her journey..." You get the idea.

## Further Reading

Academic papers and implementations we learned from:

- [SparSamp](https://arxiv.org/abs/2503.19499) (USENIX SEC 2025) — Sparse sampling for provably undetectable steganography
- [ShiMer](https://arxiv.org/abs/2501.00786) (2025) — Efficient LLM steganography via shielding and merging
- [Discop](https://ieeexplore.ieee.org/document/10179430) (IEEE S&P 2023) — Distribution-copy based steganography
- [Meteor](https://eprint.iacr.org/2021/686.pdf) (2021) — Cryptographically secure steganography for realistic distributions
- [textcoder](https://github.com/shawnz/textcoder) — Reference implementation that inspired this project

---

*Vibecoded with Claude*
