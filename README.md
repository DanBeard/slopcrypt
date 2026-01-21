# SlopCrypt

**Hide your data in slop!**

LLM steganography that embeds binary data in AI-generated text. Because if we're going to be drowning in AI slop anyway, we might as well make it useful.

## How it Works

Your secret message gets compressed, encrypted, and encoded into the token choices of an LLM. The output looks like regular AI-generated text (read: slop), but contains your hidden payload. The recipient uses the same model and shared secret to decode it.

Each token encodes `log2(K)` bits by selecting from the top-K most probable tokens. With K=16, that's 4 bits per token. Not exactly blazing throughput, but hey—it's *plausibly deniable* throughput.

## Features

- **Encrypted secrets** — PBKDF2 + AES-256-GCM (we're not animals)
- **Payload encryption** — Defeats frequency analysis on your plaintext
- **Huffman compression** — ~4-4.5 bits/char for English text
- **Knock sequence** — Find the payload without knowing the exact prompt
- **Multiple backends** — Mock client, local GGUF, MLX (Apple Silicon)

## Quickstart

```bash
# Install (using uv)
uv sync --all-extras

# Or with pip
pip install msgpack cryptography llama-cpp-python

# Generate a secret
uv run python stego_secret.py generate-secret -o my.secret

# Encode (mock client for testing)
echo "Meet at the usual place" | uv run python stego_secret.py encode --secret my.secret --mock

# Roundtrip
echo "Hello World" | uv run python stego_secret.py encode --secret my.secret --mock \
  | uv run python stego_secret.py decode --secret my.secret --mock
```

## Use with a Real Model

The mock client is for testing. For actual steganography, use a real LLM:

```bash
# Download a small model
wget https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf

# Encode
echo "Secret data" | uv run python stego_secret.py encode \
  --secret my.secret --model-path smollm2-135m-instruct-q8_0.gguf -o cover.txt

# Decode
uv run python stego_secret.py decode --secret my.secret \
  --model-path smollm2-135m-instruct-q8_0.gguf -i cover.txt
```

Or with MLX on Apple Silicon:

```bash
# Install MLX support
uv sync --extra mlx

# Encode
echo "Secret" | uv run python stego_secret.py encode --secret my.secret \
  --mlx --mlx-model mlx-community/Llama-3.2-1B-Instruct-4bit -o cover.txt

# Decode
uv run python stego_secret.py decode --secret my.secret \
  --mlx --mlx-model mlx-community/Llama-3.2-1B-Instruct-4bit -i cover.txt
```

## The Secret Blob

All the parameters live in an encrypted secret file:

```python
{
    'version': 2,
    'knock': [4, 7, 2, 9, 14, 1],  # Locates payload in the slop
    'k': 16,                        # Top-K tokens (4 bits each)
    'payload_key': <32 bytes>,      # AES key for payload
    'preamble_tokens': 10,          # Natural tokens before knock
    'suffix_tokens': 10,            # Natural tokens after payload
    'huffman_freq': {...},          # Compression frequencies
}
```

## Encoding Flow

```
Your message → Huffman compress → AES-256-GCM encrypt → Base-K encode

Cover text structure:
[Prompt] → [Preamble] → [Knock sequence] → [Encrypted payload] → [Suffix]
            ~~~~~~~~     ~~~~~~~~~~~~~~     ~~~~~~~~~~~~~~~~~~    ~~~~~~
            (natural)    (locator)          (your data)           (natural)
```

## CLI Reference

```bash
# Generate secret
uv run python stego_secret.py generate-secret -o FILE [--k K] [--knock INDICES]

# Encode
uv run python stego_secret.py encode --secret FILE [--model-path PATH | --mlx | --mock]

# Decode
uv run python stego_secret.py decode --secret FILE [--model-path PATH | --mlx | --mock]

# Inspect secret (for debugging)
uv run python stego_secret.py show-secret --secret FILE
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

## Why "SlopCrypt"?

Because the cover text is LLM-generated slop. We're not hiding data in Shakespeare—we're hiding it in "The sun set over the horizon, painting the sky in hues of orange and pink, as Sarah contemplated her journey..." You get the idea.
