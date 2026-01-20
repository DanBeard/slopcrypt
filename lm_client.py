"""
LLM client implementations for steganography.

Supports:
- llama-cpp-python (default, local CPU inference)
- LM Studio API (optional, for remote/GPU inference)
- Mock client (for testing)
"""

import math
import os
from typing import List, Optional
from dataclasses import dataclass

import httpx

from utils import TokenProb


DEFAULT_HOST = "http://192.168.1.12:1234/v1"
DEFAULT_MODEL = "local-model"

# Default model path - user should set this or pass via CLI
DEFAULT_MODEL_PATH = os.environ.get("STEGO_MODEL_PATH", None)


class LlamaCppClient:
    """
    Client using llama-cpp-python for local CPU inference.

    This is the default client - no external server needed.
    """

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 2048,
        n_gpu_layers: int = 0,
        seed: int = 42,
        top_k: int = 40,
        verbose: bool = False,
    ):
        """
        Initialize llama.cpp client.

        Args:
            model_path: Path to GGUF model file
            n_ctx: Context window size
            n_gpu_layers: Number of layers to offload to GPU (0 for CPU only)
            seed: Random seed for reproducibility
            top_k: Number of top tokens to sample from
            verbose: Print llama.cpp logs
        """
        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError(
                "llama-cpp-python not installed. Install with: pip install llama-cpp-python"
            )

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found: {model_path}\n"
                "Download a small GGUF model, e.g.:\n"
                "  wget https://huggingface.co/Qwen/Qwen2-0.5B-Instruct-GGUF/resolve/main/qwen2-0_5b-instruct-q4_k_m.gguf"
            )

        # Store params for potential model recreation
        self._model_path = model_path
        self._n_ctx = n_ctx
        self._n_gpu_layers = n_gpu_layers
        self._verbose = verbose
        self._call_count = 0

        self.model = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            # Note: seed parameter breaks logprobs in some llama.cpp versions
            # seed=seed,
            verbose=verbose,
            logits_all=True,  # Required for logprobs
        )
        self.top_k = top_k
        self.seed = seed

    def close(self):
        """Release model resources."""
        if hasattr(self, 'model'):
            del self.model

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _recreate_model(self):
        """Recreate model to fix state corruption after many calls."""
        from llama_cpp import Llama
        if hasattr(self, 'model'):
            del self.model
        self.model = Llama(
            model_path=self._model_path,
            n_ctx=self._n_ctx,
            n_gpu_layers=self._n_gpu_layers,
            verbose=self._verbose,
            logits_all=True,
        )
        self._call_count = 0

    def get_token_distribution(self, context: str) -> List[TokenProb]:
        """
        Get probability distribution over next tokens.

        Args:
            context: The text context

        Returns:
            List of TokenProb with token and probability pairs
        """
        try:
            # Reset model state to avoid corruption from previous calls
            self.model.reset()
            self._call_count = getattr(self, '_call_count', 0) + 1

            # Use temperature=1.0 to ensure we get logprobs even near EOS
            result = self.model.create_completion(
                context,
                max_tokens=1,
                logprobs=self.top_k,
                temperature=1.0,
            )

            choice = result["choices"][0]
            logprobs_data = choice.get("logprobs", {})
            top_logprobs = logprobs_data.get("top_logprobs", [])

            # Extract logprobs, filtering out empty string (EOS)
            if top_logprobs and top_logprobs[0]:
                token_logprobs = top_logprobs[0]
                output = []
                for token, logprob in token_logprobs.items():
                    # Skip empty string (EOS token)
                    if token == '':
                        continue
                    prob = math.exp(logprob)
                    output.append(TokenProb(token=token, prob=prob))

                if output:
                    # Sort by probability descending, then by token string for stability
                    # This ensures deterministic ordering when probabilities are equal
                    output.sort(key=lambda x: (-x.prob, x.token))
                    return output

            # Fallback if no logprobs - try recreating model (fixes state corruption)
            if self._call_count > 10:
                self._recreate_model()
                # Retry once
                self.model.reset()
                result = self.model.create_completion(
                    context, max_tokens=1, logprobs=self.top_k, temperature=1.0,
                )
                choice = result["choices"][0]
                top_logprobs = choice.get("logprobs", {}).get("top_logprobs", [])
                if top_logprobs and top_logprobs[0]:
                    output = []
                    for token, logprob in top_logprobs[0].items():
                        if token == '':
                            continue
                        output.append(TokenProb(token=token, prob=math.exp(logprob)))
                    if output:
                        # Sort by probability descending, then by token string for stability
                        output.sort(key=lambda x: (-x.prob, x.token))
                        return output

            token = choice.get("text", "")
            if token:
                return [TokenProb(token=token, prob=0.99)]
            return []

        except AssertionError:
            # Expected for empty context - llama.cpp requires at least one token
            return []
        except Exception as e:
            import sys
            print(f"Warning: Model error: {type(e).__name__}: {e}", file=sys.stderr)
            return []

    def tokenize(self, text: str) -> List[str]:
        """Tokenize text using the model's tokenizer."""
        token_ids = self.model.tokenize(text.encode('utf-8'))
        tokens = []
        for tid in token_ids:
            token_bytes = self.model.detokenize([tid])
            try:
                token_str = token_bytes.decode('utf-8', errors='replace')
            except:
                token_str = token_bytes.decode('latin-1', errors='replace')
            tokens.append(token_str)
        return tokens


@dataclass
class LMConfig:
    """Configuration for LM Studio connection."""
    host: str = DEFAULT_HOST
    model: str = DEFAULT_MODEL
    top_logprobs: int = 10  # LM Studio Open Responses API limit
    temperature: float = 0.0  # Use 0 for deterministic distributions
    seed: Optional[int] = 42


class LMClient:
    """
    Client for interacting with LM Studio API.

    Uses the Open Responses API (/v1/responses) which supports logprobs.
    Requires LM Studio 0.3.39+.
    """

    def __init__(self, config: Optional[LMConfig] = None):
        """
        Initialize the LM Studio client.

        Args:
            config: Configuration for the client
        """
        self.config = config or LMConfig()
        self.client = httpx.Client(timeout=60.0)

    def close(self):
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def get_token_distribution(self, context: str) -> List[TokenProb]:
        """
        Get probability distribution over next tokens given context.

        Uses LM Studio's Open Responses API which returns logprobs.

        Args:
            context: The text context (prompt + generated text so far)

        Returns:
            List of TokenProb with token and probability pairs
        """
        # Use Open Responses API - remove /v1 suffix if present, then add /v1/responses
        base_host = self.config.host.rstrip('/')
        if base_host.endswith('/v1'):
            base_host = base_host[:-3]
        url = f"{base_host}/v1/responses"

        payload = {
            "model": self.config.model,
            "instructions": "Continue the text naturally. Output only the continuation, nothing else.",
            "input": context,  # String input, not array
            "max_output_tokens": 10,  # Need enough tokens for reasoning models
            "temperature": self.config.temperature,
            "include": ["message.output_text.logprobs"],
            "top_logprobs": self.config.top_logprobs,
        }

        response = self.client.post(url, json=payload)
        if response.status_code != 200:
            raise RuntimeError(f"LM Studio API error {response.status_code}: {response.text}")
        response.raise_for_status()

        data = response.json()

        # Extract logprobs from Open Responses format
        try:
            # Open Responses format: output[].content[].logprobs[]
            # Find the "message" output (skip "reasoning" outputs from thinking models)
            output_list = data.get("output", [])
            if not output_list:
                return []

            # Look for message type output (not reasoning)
            for output in output_list:
                if output.get("type") != "message":
                    continue

                content = output.get("content", [])
                for item in content:
                    if item.get("type") == "output_text":
                        logprobs_list = item.get("logprobs", [])
                        if logprobs_list:
                            # Get first token's logprobs
                            first_token = logprobs_list[0]
                            result = []

                            # Add all top candidates
                            for candidate in first_token.get("top_logprobs", []):
                                ctoken = candidate.get("token", "")
                                clogprob = candidate.get("logprob", 0)
                                if ctoken:
                                    result.append(TokenProb(token=ctoken, prob=math.exp(clogprob)))

                            # If no top_logprobs, use the selected token
                            if not result:
                                token = first_token.get("token", "")
                                logprob = first_token.get("logprob", 0)
                                if token:
                                    result.append(TokenProb(token=token, prob=math.exp(logprob)))

                            result.sort(key=lambda x: x.prob, reverse=True)
                            return result

                        # No logprobs, just return the text
                        text = item.get("text", "")
                        if text:
                            return [TokenProb(token=text, prob=1.0)]

            return []

        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Failed to parse logprobs from response: {e}\nResponse: {data}")


class MockLMClient:
    """
    Mock LM client for testing without LM Studio.

    Generates deterministic distributions based on context hash.
    """

    def __init__(self, vocab_size: int = 32, seed: int = 42):
        """
        Initialize mock client.

        Args:
            vocab_size: Number of tokens in vocabulary
            seed: Random seed for reproducibility
        """
        self.vocab_size = vocab_size
        self.seed = seed
        # Simple vocabulary of common words/tokens
        self.vocab = [
            " the", " a", " an", " is", " was", " are", " were", " be",
            " been", " being", " have", " has", " had", " do", " does",
            " did", " will", " would", " could", " should", " may", " might",
            " must", " shall", " can", " need", " dare", " ought", " used",
            " to", " of", " in",
        ][:vocab_size]

    def _hash_context(self, context: str) -> int:
        """Generate deterministic hash from context."""
        h = self.seed
        for c in context:
            h = ((h * 31) + ord(c)) & 0xFFFFFFFF
        return h

    def get_token_distribution(self, context: str) -> List[TokenProb]:
        """Generate deterministic distribution based on context."""
        h = self._hash_context(context)

        # Generate probabilities using the hash
        probs = []
        remaining = 1.0

        for i, token in enumerate(self.vocab):
            # Use hash to generate pseudo-random probability
            token_hash = ((h * (i + 1)) ^ (h >> 16)) & 0xFFFFFFFF
            # Zipf-like distribution: earlier tokens more likely
            base_prob = 1.0 / (i + 1)
            noise = (token_hash % 1000) / 10000.0  # Small noise
            prob = base_prob + noise
            probs.append(prob)

        # Normalize
        total = sum(probs)
        result = [
            TokenProb(token=self.vocab[i], prob=probs[i] / total)
            for i in range(len(self.vocab))
        ]

        # Sort by probability descending
        result.sort(key=lambda x: x.prob, reverse=True)

        return result

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
