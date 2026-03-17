"""
Decoy traffic generator for SlopLink.

Generates natural-looking LLM text (with no hidden payload) at random
intervals to prevent timing analysis and maintain plausible deniability.
Both peers generate decoy traffic independently.
"""

from __future__ import annotations

import random
import sys
import threading

from slopcrypt.encode import sample_from_distribution
from slopcrypt.utils import filter_prefix_tokens


def generate_slop(
    client,
    prompt: str,
    system_prompt: str = "",
    k: int = 16,
    num_tokens: int = 50,
    temperature: float = 0.8,
) -> str:
    """
    Generate natural LLM text with no hidden payload.

    Uses the same model and parameters as real messages, so the output
    is statistically indistinguishable from cover text that contains
    a hidden payload.

    Args:
        client: LLM client (same one used for encoding).
        prompt: Visible prompt (conversation context).
        system_prompt: Hidden system prompt for the LLM.
        k: Top-K tokens to consider (must match encoding config).
        num_tokens: Number of tokens to generate.
        temperature: Sampling temperature.

    Returns:
        Generated text (without the prompt prefix).
    """
    context = system_prompt + prompt
    tokens = []

    for _ in range(num_tokens):
        dist = client.get_token_distribution(context)
        if not dist:
            break
        top_k = filter_prefix_tokens(dist, k)
        if not top_k:
            break
        _, token = sample_from_distribution(top_k, temperature)
        tokens.append(token)
        context += token

    return "".join(tokens)


class DecoyManager:
    """
    Manages bidirectional decoy traffic for a SlopLink peer.

    Generates and sends natural LLM text at Poisson-distributed intervals.
    The mean interval and token count are configurable. Each peer runs
    its own DecoyManager independently.
    """

    def __init__(
        self,
        send_fn,
        client,
        get_prompt_fn,
        system_prompt: str = "",
        k: int = 16,
        mean_interval: float = 120.0,
        min_tokens: int = 20,
        max_tokens: int = 80,
        temperature: float = 0.8,
    ):
        """
        Args:
            send_fn: Callable that sends text via the chat transport AND
                     adds it to conversation context.
            client: LLM client for generating text.
            get_prompt_fn: Callable that returns the current conversation prompt.
            system_prompt: System prompt for LLM generation.
            k: Top-K parameter matching the secret config.
            mean_interval: Mean seconds between decoy messages.
            min_tokens: Minimum tokens per decoy message.
            max_tokens: Maximum tokens per decoy message.
            temperature: Sampling temperature.
        """
        self.send_fn = send_fn
        self.client = client
        self.get_prompt_fn = get_prompt_fn
        self.system_prompt = system_prompt
        self.k = k
        self.mean_interval = mean_interval
        self.min_tokens = min_tokens
        self.max_tokens = max_tokens
        self.temperature = temperature

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start generating decoy traffic in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop decoy traffic generation."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        """Main decoy generation loop with Poisson-distributed timing."""
        while self._running:
            # Poisson inter-arrival time
            delay = random.expovariate(1.0 / self.mean_interval)
            # Clamp to reasonable range
            delay = max(10.0, min(delay, self.mean_interval * 5))

            if self._stop_event.wait(timeout=delay):
                break

            if not self._running:
                break

            try:
                self._send_decoy()
            except Exception as e:
                print(f"[SlopLink] Decoy generation error: {e}", file=sys.stderr)

    def _send_decoy(self) -> None:
        """Generate and send a single decoy message."""
        prompt = self.get_prompt_fn()
        num_tokens = random.randint(self.min_tokens, self.max_tokens)

        slop = generate_slop(
            client=self.client,
            prompt=prompt,
            system_prompt=self.system_prompt,
            k=self.k,
            num_tokens=num_tokens,
            temperature=self.temperature,
        )

        if slop.strip():
            self.send_fn(slop)
