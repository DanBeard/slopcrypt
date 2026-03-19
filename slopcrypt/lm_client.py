"""
LLM client implementations for steganography.

Supports:
- llama-cpp-python (default, local CPU inference)
- LM Studio API (optional, for remote/GPU inference)
- Mock client (for testing)
"""

import math
import os
from dataclasses import dataclass

import httpx
import numpy as np

from slopcrypt.utils import TokenProb

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
        except ImportError as e:
            raise ImportError(
                "llama-cpp-python not installed. Install with: pip install llama-cpp-python"
            ) from e

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
        if hasattr(self, "model"):
            del self.model

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _recreate_model(self):
        """Recreate model to fix state corruption after many calls."""
        from llama_cpp import Llama

        if hasattr(self, "model"):
            del self.model
        self.model = Llama(
            model_path=self._model_path,
            n_ctx=self._n_ctx,
            n_gpu_layers=self._n_gpu_layers,
            verbose=self._verbose,
            logits_all=True,
        )
        self._call_count = 0

    def get_token_distribution(self, context: str) -> list[TokenProb]:
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
            self._call_count = getattr(self, "_call_count", 0) + 1

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
                    if token == "":
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
                    context,
                    max_tokens=1,
                    logprobs=self.top_k,
                    temperature=1.0,
                )
                choice = result["choices"][0]
                top_logprobs = choice.get("logprobs", {}).get("top_logprobs", [])
                if top_logprobs and top_logprobs[0]:
                    output = []
                    for token, logprob in top_logprobs[0].items():
                        if token == "":
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

    def tokenize(self, text: str) -> list[str]:
        """Tokenize text using the model's tokenizer."""
        token_ids = self.model.tokenize(text.encode("utf-8"))
        tokens = []
        for tid in token_ids:
            token_bytes = self.model.detokenize([tid])
            try:
                token_str = token_bytes.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                token_str = token_bytes.decode("latin-1", errors="replace")
            tokens.append(token_str)
        return tokens


class CachedLlamaCppClient:
    """
    High-performance llama.cpp client with KV cache reuse.

    Instead of resetting the model and re-processing the entire context
    for every token (O(n²) total work), this client maintains the KV cache
    across calls. When the new context extends the previous one (which is
    always the case during steganographic encoding), only the new token
    needs a forward pass — giving O(n) total work and ~100-300x speedup.

    Falls back to full re-eval when the context doesn't extend the cache
    (e.g., when switching between encode and decode operations).
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
        try:
            from llama_cpp import Llama
        except ImportError as e:
            raise ImportError(
                "llama-cpp-python not installed. Install with: pip install llama-cpp-python"
            ) from e

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")

        self.model = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=verbose,
            logits_all=False,  # Only need last-position logits
        )
        self.top_k = top_k
        self._n_vocab = self.model._n_vocab

        # Cache state: the token IDs currently in the KV cache
        self._cached_tokens: list[int] = []

    def close(self):
        if hasattr(self, "model"):
            del self.model

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _get_logits(self) -> np.ndarray:
        """Read logits for the last evaluated position."""
        logits_ptr = self.model._ctx.get_logits()
        return np.ctypeslib.as_array(logits_ptr, shape=(self._n_vocab,)).copy()

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """
        Get probability distribution over next tokens, reusing KV cache.

        If `context` extends the previously cached context (i.e., tokens
        were appended), only the new tokens are evaluated. Otherwise, the
        cache is cleared and the full context is re-evaluated.
        """
        new_tokens = self.model.tokenize(context.encode("utf-8"))

        # Check if the new tokens extend the cached ones
        cache_len = len(self._cached_tokens)
        if (
            cache_len > 0
            and len(new_tokens) >= cache_len
            and new_tokens[:cache_len] == self._cached_tokens
        ):
            # Cache hit: only eval the new tokens
            tokens_to_eval = new_tokens[cache_len:]
        else:
            # Cache miss: reset and eval everything
            self.model.reset()
            self._cached_tokens = []
            tokens_to_eval = new_tokens

        if not tokens_to_eval:
            # Context unchanged — logits are already current
            pass
        else:
            self.model.eval(tokens_to_eval)

        self._cached_tokens = new_tokens

        # Read logits and compute probabilities
        try:
            logits = self._get_logits()
            # Numerically stable softmax
            logits_shifted = logits - logits.max()
            probs = np.exp(logits_shifted)
            probs /= probs.sum()

            # Get top-K indices
            top_indices = np.argpartition(probs, -self.top_k)[-self.top_k :]
            top_indices = top_indices[np.argsort(probs[top_indices])[::-1]]

            result = []
            for idx in top_indices:
                idx_int = int(idx)
                token_bytes = self.model.detokenize([idx_int])
                token_str = token_bytes.decode("utf-8", errors="replace")
                if token_str:  # Skip empty (EOS)
                    result.append(TokenProb(token=token_str, prob=float(probs[idx_int])))

            # Sort by probability descending, then by token string for stability
            result.sort(key=lambda x: (-x.prob, x.token))
            return result

        except Exception as e:
            import sys
            print(f"Warning: CachedLlamaCppClient error: {e}", file=sys.stderr)
            return []

    def reset_cache(self):
        """Force clear the KV cache (e.g., when switching contexts)."""
        self.model.reset()
        self._cached_tokens = []


@dataclass
class LMConfig:
    """Configuration for LM Studio connection."""

    host: str = DEFAULT_HOST
    model: str = DEFAULT_MODEL
    top_logprobs: int = 10  # LM Studio Open Responses API limit
    temperature: float = 0.0  # Use 0 for deterministic distributions
    seed: int | None = 42


class LMClient:
    """
    Client for interacting with LM Studio API.

    Uses the Open Responses API (/v1/responses) which supports logprobs.
    Requires LM Studio 0.3.39+.
    """

    def __init__(self, config: LMConfig | None = None):
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

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """
        Get probability distribution over next tokens given context.

        Uses LM Studio's Open Responses API which returns logprobs.

        Args:
            context: The text context (prompt + generated text so far)

        Returns:
            List of TokenProb with token and probability pairs
        """
        # Use Open Responses API - remove /v1 suffix if present, then add /v1/responses
        base_host = self.config.host.rstrip("/")
        if base_host.endswith("/v1"):
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
            raise RuntimeError(
                f"Failed to parse logprobs from response: {e}\nResponse: {data}"
            ) from e


class MLXClient:
    """
    Client using MLX for Apple Silicon inference.

    Uses mlx-lm's direct API to get full vocabulary logprobs,
    which is required for K>10 (server API limits to 10 tokens).
    """

    def __init__(
        self,
        model_name: str,
        top_k: int = 40,
        seed: int = 42,
    ):
        """
        Initialize MLX client.

        Args:
            model_name: HuggingFace model name (e.g., mlx-community/Llama-3.2-1B-Instruct-4bit)
            top_k: Number of top tokens to return
            seed: Random seed for reproducibility
        """
        try:
            from mlx_lm import load, stream_generate
            import mlx.core as mx
        except ImportError as e:
            raise ImportError(
                "mlx-lm not installed. Install with: pip install mlx-lm\n"
                "Note: MLX only works on Apple Silicon Macs."
            ) from e

        self._mx = mx
        self._stream_generate = stream_generate
        self.model, self.tokenizer = load(model_name)
        self.top_k = top_k
        mx.random.seed(seed)
        self._special_ids = set(getattr(self.tokenizer, "all_special_ids", []))

    def get_token_distribution(self, context: str) -> list["TokenProb"]:
        """
        Get probability distribution over next tokens.

        Args:
            context: The text context

        Returns:
            List of TokenProb with token and probability pairs
        """
        mx = self._mx
        prompt_tokens = self.tokenizer.encode(context)

        # Get one generation step for logprobs
        for response in self._stream_generate(
            self.model, self.tokenizer, mx.array(prompt_tokens), max_tokens=1
        ):
            logprobs = response.logprobs
            break
        else:
            return []

        # Top-K indices descending by logprob
        top_k_indices = mx.argsort(logprobs)[-self.top_k :][::-1]

        result = []
        for idx in top_k_indices:
            idx_int = int(idx)
            if idx_int in self._special_ids:
                continue
            token_str = self.tokenizer.decode([idx_int])
            if not token_str:
                continue
            prob = float(mx.exp(logprobs[idx_int]))
            result.append(TokenProb(token=token_str, prob=prob))

        # Sort by probability descending, then by token string for stability
        result.sort(key=lambda x: (-x.prob, x.token))
        return result

    def close(self):
        """Release model resources."""
        if hasattr(self, "model"):
            del self.model

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


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
            " the",
            " a",
            " an",
            " is",
            " was",
            " are",
            " were",
            " be",
            " been",
            " being",
            " have",
            " has",
            " had",
            " do",
            " does",
            " did",
            " will",
            " would",
            " could",
            " should",
            " may",
            " might",
            " must",
            " shall",
            " can",
            " need",
            " dare",
            " ought",
            " used",
            " to",
            " of",
            " in",
        ][:vocab_size]

    def _hash_context(self, context: str) -> int:
        """Generate deterministic hash from context."""
        h = self.seed
        for c in context:
            h = ((h * 31) + ord(c)) & 0xFFFFFFFF
        return h

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """Generate deterministic distribution based on context."""
        h = self._hash_context(context)

        # Generate probabilities using the hash
        probs = []

        for i, _token in enumerate(self.vocab):
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
            TokenProb(token=self.vocab[i], prob=probs[i] / total) for i in range(len(self.vocab))
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


class MarkovClient:
    """
    Markov chain client for ultra-fast steganographic encoding.

    Uses markovify to build an N-gram transition model from a text corpus.
    Each call to get_token_distribution() is a single dict lookup + normalize,
    giving ~100,000+ calls/sec on any hardware — no GPU, no C extensions.

    Both peers must share the same trained model (JSON file) for identical
    probability distributions.

    Usage:
        # Train from a corpus
        client = MarkovClient.from_corpus("garden_forum_posts.txt", state_size=2)
        client.save("garden.markov.json")

        # Load for encode/decode
        client = MarkovClient.from_file("garden.markov.json")
        dist = client.get_token_distribution("growing tomatoes in")
    """

    def __init__(self, model, state_size: int = 2, smoothing: float = 0.1, top_k: int = 64):
        """
        Args:
            model: A markovify.Text model (uncompiled).
            state_size: N-gram size used for context lookups.
            smoothing: Weight given to the global unigram distribution
                      (0.0 = pure Markov, 1.0 = pure unigram). This
                      ensures every state has a rich distribution by
                      blending with a background model.
            top_k: Only keep the top-K tokens per state (saves memory
                  and speeds up precompute for large corpora).
        """
        self._model = model
        self._state_size = state_size
        self._smoothing = smoothing
        self._top_k = top_k
        # Pre-compute normalized distributions for speed
        self._distributions: dict[tuple, list[TokenProb]] = {}
        self._unigram_top: list[tuple[str, float]] = []
        self._precompute()

    def _precompute(self) -> None:
        """Convert raw counts to smoothed, normalized TokenProb lists."""
        chain_model = self._model.chain.model

        # First pass: build global unigram counts
        word_counts: dict[str, int] = {}
        for state, successors in chain_model.items():
            for word, count in successors.items():
                if word is None or not isinstance(word, str):
                    continue
                if word.startswith("___"):
                    continue
                word_counts[word] = word_counts.get(word, 0) + count

        total_unigram = sum(word_counts.values())

        # Keep only top unigram words for efficiency (the long tail
        # contributes negligible probability after smoothing)
        top_unigram_n = self._top_k * 4
        sorted_words = sorted(word_counts.items(), key=lambda x: -x[1])[:top_unigram_n]
        unigram_total = sum(c for _, c in sorted_words)
        self._unigram_top = [
            (w, c / unigram_total) for w, c in sorted_words
        ]

        # Second pass: blend each state's distribution with unigram
        alpha = self._smoothing
        for state, successors in chain_model.items():
            state_total = sum(
                c for w, c in successors.items()
                if w is not None and isinstance(w, str)
            )
            if state_total == 0:
                continue

            # Merge state distribution with top unigram background
            merged: dict[str, float] = {}

            # State-specific probabilities (weight: 1 - alpha)
            for word, count in successors.items():
                if word is None or not isinstance(word, str):
                    continue
                # Skip markovify internal markers
                if word.startswith("___"):
                    continue
                merged[word] = (1 - alpha) * (count / state_total)

            # Unigram background (weight: alpha)
            for word, prob in self._unigram_top:
                merged[word] = merged.get(word, 0) + alpha * prob

            # Keep only top-K, normalize, convert to TokenProb
            top_items = sorted(merged.items(), key=lambda x: -x[1])[:self._top_k]
            total = sum(p for _, p in top_items)
            probs = [
                TokenProb(token=" " + w, prob=p / total)
                for w, p in top_items
            ]
            probs.sort(key=lambda x: (-x.prob, x.token))
            self._distributions[state] = probs

        # Note: prefix filtering is NOT done here. The lite codec
        # (sloplink/codec.py) handles word-boundary matching during
        # decode, which avoids prefix ambiguity without removing tokens.

    @classmethod
    def from_corpus(
        cls,
        text: str,
        state_size: int = 2,
        well_formed: bool = False,
        smoothing: float = 0.1,
    ) -> "MarkovClient":
        """
        Train a Markov chain from a text corpus.

        Args:
            text: The training corpus as a single string.
            state_size: N-gram context size (2 = bigram, 3 = trigram).
            well_formed: If False, disables markovify's sentence validation
                        for more diverse output (better for steganography).
            smoothing: Blend weight with global unigram distribution (0-1).
        """
        try:
            import markovify
        except ImportError as e:
            raise ImportError(
                "markovify not installed. Install with: pip install markovify"
            ) from e

        model = markovify.Text(text, state_size=state_size, well_formed=well_formed)
        return cls(model, state_size=state_size, smoothing=smoothing)

    @classmethod
    def from_file(cls, path: str) -> "MarkovClient":
        """Load a trained Markov chain from a JSON file."""
        try:
            import markovify
        except ImportError as e:
            raise ImportError(
                "markovify not installed. Install with: pip install markovify"
            ) from e

        with open(path) as f:
            json_str = f.read()
        model = markovify.Text.from_json(json_str)
        state_size = len(next(iter(model.chain.model.keys())))
        return cls(model, state_size=state_size)

    def save(self, path: str) -> None:
        """Save the trained model to a JSON file."""
        with open(path, "w") as f:
            f.write(self._model.to_json())

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """
        Get probability distribution over next tokens given context.

        Extracts the last `state_size` words from context and looks up
        the transition probabilities. Falls back to shorter contexts
        if the full state isn't found.
        """
        words = context.split()

        # Try full state, then progressively shorter
        for n in range(self._state_size, 0, -1):
            if len(words) >= n:
                state = tuple(words[-n:])
                # Pad to state_size with markovify's BEGIN marker if needed
                if n < self._state_size:
                    state = ("___BEGIN__",) * (self._state_size - n) + state
                dist = self._distributions.get(state)
                if dist:
                    return dist

        # Try BEGIN state (start of sentence)
        begin_state = ("___BEGIN__",) * self._state_size
        dist = self._distributions.get(begin_state)
        if dist:
            return dist

        # Absolute fallback: return most common state's distribution
        if self._distributions:
            return next(iter(self._distributions.values()))

        return []

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FixedDistributionClient:
    """
    LM client that returns a fixed, deterministic distribution.

    Used for cross-language compatibility testing where Python and TypeScript
    implementations must produce identical results. Unlike mock clients which
    use context-dependent hashing (which differs between languages), this
    client always returns the same hard-coded distribution.
    """

    # 32 tokens with probabilities summing to 1.0
    # These are sorted by probability descending, then by token string.
    # MUST be identical to TypeScript's FixedDistributionClient.FIXED_VOCAB
    FIXED_VOCAB: list[tuple[str, float]] = [
        (" the", 0.12),
        (" a", 0.10),
        (" to", 0.08),
        (" and", 0.07),
        (" of", 0.06),
        (" in", 0.05),
        (" is", 0.045),
        (" that", 0.04),
        (" it", 0.035),
        (" for", 0.03),
        (" was", 0.028),
        (" on", 0.026),
        (" with", 0.024),
        (" as", 0.022),
        (" be", 0.02),
        (" at", 0.018),
        (" by", 0.016),
        (" this", 0.015),
        (" from", 0.014),
        (" or", 0.013),
        (" an", 0.012),
        (" but", 0.011),
        (" not", 0.010),
        (" are", 0.009),
        (" have", 0.008),
        (" were", 0.007),
        (" been", 0.006),
        (" has", 0.005),
        (" their", 0.004),
        (" which", 0.003),
        (" when", 0.002),
        (" there", 0.001),
    ]

    def __init__(self, vocab_size: int = 32):
        """
        Initialize fixed distribution client.

        Args:
            vocab_size: Number of tokens to return (max 32)
        """
        self.vocab_size = min(vocab_size, len(self.FIXED_VOCAB))

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """
        Return fixed distribution regardless of context.

        The distribution is always the same, ensuring identical behavior
        across Python and TypeScript implementations.
        """
        return [
            TokenProb(token=token, prob=prob)
            for token, prob in self.FIXED_VOCAB[: self.vocab_size]
        ]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
