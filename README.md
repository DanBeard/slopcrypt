# LLM Steganography

Hide binary data in LLM-generated text using Base-K encoding.

## Quickstart

### 1. Install dependencies

```bash
pip install httpx llama-cpp-python
```

### 2. Basic usage (mock client for testing)

```bash
# Encode a message
echo "Secret message" | python stego_basek.py encode --mock

# Full roundtrip - encode then decode
echo "Hello World" | python stego_basek.py encode --mock | python stego_basek.py decode --mock
```

### 3. Encode a file

```bash
# Encode a file to cover text
python stego_basek.py encode -i secret.txt -o cover.txt --mock

# Decode back
python stego_basek.py decode -i cover.txt -o recovered.txt --mock

# Verify
diff secret.txt recovered.txt
```

### 4. Use with LM Studio

LM Studio 0.3.39+ supports logprobs via the Open Responses API.

```bash
# Encode with LM Studio (requires --model)
echo "Secret" | python stego_basek.py encode \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct

# Full roundtrip
echo "Hello World" | python stego_basek.py encode \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct \
  | python stego_basek.py decode \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct
```

**Notes:**
- K is automatically set to 4 (2 bits/token) for reliability with LM Studio
- Use non-reasoning models like `llama-3.2-1b-instruct`
- Reasoning models (qwen3) need `/no_think` in the prompt and have less varied distributions
- The cover text will look repetitive but decodes correctly

### 5. Use with a local GGUF model

Download a GGUF model:
```bash
wget https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q8_0.gguf
```

Encode/decode:
```bash
python stego_basek.py encode -i secret.bin --model-path smollm2-135m-instruct-q8_0.gguf -o cover.txt
python stego_basek.py decode -i cover.txt --model-path smollm2-135m-instruct-q8_0.gguf -o recovered.bin
```

## How it works

Base-K steganography maps each `log2(K)` bits of your data to one of the top-K most likely tokens from the LLM's probability distribution. With the default K=16, each token encodes 4 bits.

The encoder and decoder must use the same:
- Model (or mock client)
- Prompt
- K value

## Options

```
usage: stego_basek.py [-h] [-i INPUT] [-o OUTPUT] [-k K] [--prompt PROMPT]
                      [--model-path MODEL_PATH] [--lmstudio] [--host HOST]
                      [--model MODEL] [--mock] [-v]
                      {encode,decode}

Arguments:
  {encode,decode}       Operation mode

Options:
  -i, --input           Input file (default: stdin)
  -o, --output          Output file (default: stdout)
  -k K                  Top-K tokens to use (default: 16, must be power of 2)
  --prompt PROMPT       Initial prompt for generation
  --model-path PATH     Path to GGUF model file (for llama-cpp-python)
  --lmstudio            Use LM Studio API instead of local model
  --host URL            LM Studio API URL (default: http://192.168.1.12:1234/v1)
  --model MODEL         Model name for LM Studio (e.g., llama-3.2-1b-instruct)
  --mock                Use mock client (for testing)
  -v, --verbose         Show progress
```

## Examples

```bash
# Encode with higher capacity (5 bits/token, mock only - LM Studio limited to K=8)
echo "data" | python stego_basek.py encode --mock -k 32

# Encode with verbose output
python stego_basek.py encode -i secret.bin --mock -v

# Use custom prompt (must match for encode and decode!)
echo "Hi" | python stego_basek.py encode --mock --prompt "Once upon a time" \
  | python stego_basek.py decode --mock --prompt "Once upon a time"

# Use LM Studio with a specific model
echo "Secret data" | python stego_basek.py encode \
  --lmstudio --host http://localhost:1234/v1 --model llama-3.2-1b-instruct
```

## Run tests

```bash
python test_stego.py
```
