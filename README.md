# SlopCrypt

Hide binary data in LLM-generated text using Base-K steganography with encrypted secrets.

## Features

- **Encrypted secrets**: Password-protected secret blob (PBKDF2 + AES-256-GCM)
- **Payload encryption**: Encrypted payload defeats frequency analysis
- **Huffman compression**: ~4-4.5 bits/char for English text
- **Knock sequence**: Locates payload without needing exact prompt match
- **Multiple backends**: Mock client, local GGUF models, LM Studio API

## Quickstart

### 1. Install dependencies

```bash
pip install msgpack cryptography httpx llama-cpp-python pytest
```

### 2. Generate a secret

```bash
# Generate with password prompt
python stego_secret.py generate-secret -o my.secret

# Or with explicit password
python stego_secret.py generate-secret -o my.secret --password mypassword

# With custom parameters
python stego_secret.py generate-secret -o my.secret --k 16 --knock 4,7,2,9,14,1
```

### 3. Encode and decode (mock client)

```bash
# Encode a message
echo "Secret message" | python stego_secret.py encode --secret my.secret --mock

# Full roundtrip
echo "Hello World" | python stego_secret.py encode --secret my.secret --mock \
  | python stego_secret.py decode --secret my.secret --mock
```

### 4. Use with a local GGUF model

Download a model:
```bash
wget https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf
```

Encode/decode:
```bash
# Encode
echo "Secret data" | python stego_secret.py encode \
  --secret my.secret --model-path smollm2-135m-instruct-q8_0.gguf -o cover.txt

# Decode
python stego_secret.py decode --secret my.secret \
  --model-path smollm2-135m-instruct-q8_0.gguf -i cover.txt
```

### 5. Use with LM Studio

LM Studio 0.3.39+ supports logprobs via the Open Responses API.

```bash
# Encode
echo "Secret" | python stego_secret.py encode --secret my.secret \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct

# Decode
python stego_secret.py decode --secret my.secret \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct -i cover.txt
```

## How it works

### Base-K Encoding

Each `log2(K)` bits of data maps to one of the top-K most likely tokens from the LLM's probability distribution. With K=16 (default), each token encodes 4 bits.

### Secret Blob

The secret contains all parameters needed for encoding/decoding:

```python
{
    'version': 2,
    'knock': [4, 7, 2, 9, 14, 1],  # Locates payload in cover text
    'k': 16,                        # Top-K tokens (bits per token = log2(k))
    'payload_key': <32 bytes>,      # AES-256 key for payload encryption
    'preamble_tokens': 10,          # Natural tokens before knock
    'suffix_tokens': 10,            # Natural tokens after payload
    'temperature': 0.8,
    'huffman_freq': {...},          # Compression frequencies
}
```

### Encoding Flow

```
Message → Huffman compress → AES-256-GCM encrypt → Base-K encode

Cover text structure:
[Prompt] → [Preamble] → [Knock sequence] → [Length + Encrypted payload] → [Suffix]
```

The knock sequence allows the decoder to locate the payload without needing the exact prompt.

## CLI Reference

### stego_secret.py (recommended)

```bash
# Generate secret
python stego_secret.py generate-secret -o FILE [--k K] [--knock INDICES] [--password PASS]

# Encode message
python stego_secret.py encode --secret FILE [--model-path PATH | --lmstudio | --mock]
  [-i INPUT] [-o OUTPUT] [--prompt PROMPT] [--password PASS]

# Decode message
python stego_secret.py decode --secret FILE [--model-path PATH | --lmstudio | --mock]
  [-i INPUT] [-o OUTPUT] [--password PASS]

# Show secret parameters
python stego_secret.py show-secret --secret FILE [--password PASS]
```

### stego_basek.py (low-level)

For debugging or direct access to the base-K encoding:

```bash
python stego_basek.py encode [--knock INDICES] [--preamble N] [--suffix N] ...
python stego_basek.py decode [--knock INDICES] ...
```

## Run tests

```bash
# All tests
python -m pytest test_stego_secret.py test_stego.py -v

# Just the secret wrapper tests
python -m pytest test_stego_secret.py -v
```

## Security Notes

- Secret blob is encrypted with AES-256-GCM using a PBKDF2-derived key (600k iterations)
- Payload is separately encrypted with AES-256-GCM using a random key stored in the secret
- Huffman compression happens before encryption (no frequency analysis possible)
- The knock sequence and K value must remain secret for security
