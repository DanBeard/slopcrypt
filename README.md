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
- **Multiple backends** — Mock client, local GGUF, LM Studio API

## Quickstart

```bash
# Install
pip install msgpack cryptography httpx llama-cpp-python

# Generate a secret
python stego_secret.py generate-secret -o my.secret

# Encode (mock client for testing)
echo "Meet at the usual place" | python stego_secret.py encode --secret my.secret --mock

# Roundtrip
echo "Hello World" | python stego_secret.py encode --secret my.secret --mock \
  | python stego_secret.py decode --secret my.secret --mock
```

## Use with a Real Model

The mock client is for testing. For actual steganography, use a real LLM:

```bash
# Download a small model
wget https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf

# Encode
echo "Secret data" | python stego_secret.py encode \
  --secret my.secret --model-path smollm2-135m-instruct-q8_0.gguf -o cover.txt

# Decode
python stego_secret.py decode --secret my.secret \
  --model-path smollm2-135m-instruct-q8_0.gguf -i cover.txt
```

Or with LM Studio (0.3.39+):

```bash
echo "Secret" | python stego_secret.py encode --secret my.secret \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct
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
python stego_secret.py generate-secret -o FILE [--k K] [--knock INDICES]

# Encode
python stego_secret.py encode --secret FILE [--model-path PATH | --lmstudio | --mock]

# Decode
python stego_secret.py decode --secret FILE [--model-path PATH | --lmstudio | --mock]

# Inspect secret (for debugging)
python stego_secret.py show-secret --secret FILE
```

## Tests

```bash
python -m pytest test_stego_secret.py test_stego.py -v
```

## Security Notes

- Secret blob: AES-256-GCM with PBKDF2-derived key (600k iterations)
- Payload: separately encrypted with AES-256-GCM
- Compression happens *before* encryption (no frequency leaks)
- Keep your `.secret` file... secret

## Why "SlopCrypt"?

Because the cover text is LLM-generated slop. We're not hiding data in Shakespeare—we're hiding it in "The sun set over the horizon, painting the sky in hues of orange and pink, as Sarah contemplated her journey..." You get the idea.
