"""
Integration tests for SlopLink.

By default, uses a RichMockLMClient — a deterministic mock with a large,
realistic vocabulary that exercises the full pipeline without needing a
GPU or model download.

To run with a real SmolLM2 (requires llama-cpp-python + ~145MB download):
    SLOPLINK_USE_REAL_LLM=1 python -m pytest tests/test_sloplink_integration.py -v

Or point to your own GGUF:
    SLOPLINK_TEST_MODEL=/path/to/model.gguf SLOPLINK_USE_REAL_LLM=1 \
        python -m pytest tests/test_sloplink_integration.py -v
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import sys
import tempfile
import threading
import time

import pytest

from slopcrypt.secret import decode_message, encode_message, generate_secret
from slopcrypt.sloplink.context import ConversationContext
from slopcrypt.sloplink.decoy import generate_slop
from slopcrypt.sloplink.interface import (
    DEFAULT_ROLE_PROMPTS,
    DEFAULT_SEED_PROMPT,
    SlopLinkInterface,
)
from slopcrypt.sloplink.transport import UnixSocketTransport
from slopcrypt.utils import TokenProb

# ---------------------------------------------------------------------------
# Rich mock LLM client
# ---------------------------------------------------------------------------

# 128 tokens that look like realistic LLM output fragments.
# Includes word tokens, punctuation, subwords — enough variety for
# convincing steganography while staying fully deterministic.
RICH_VOCAB = [
    " the", " a", " to", " and", " of", " in", " is", " that",
    " it", " for", " was", " on", " with", " as", " be", " at",
    " by", " this", " from", " or", " an", " but", " not", " are",
    " have", " were", " been", " has", " their", " which", " when",
    " there", " what", " about", " would", " can", " more", " if",
    " had", " all", " will", " one", " do", " my", " its", " just",
    " so", " you", " your", " like", " how", " up", " out", " some",
    " could", " them", " than", " into", " also", " then", " very",
    " well", " know", " time", " think", " good", " over", " new",
    " because", " people", " way", " right", " now", " after",
    " really", " most", " where", " much", " get", " through",
    " back", " only", " being", " still", " here", " should",
    " many", " other", " make", " even", " first", " while",
    " great", " world", " never", " going", " same", " those",
    " long", " day", " help", " look", " see", " work", " want",
    " between", " need", " say", " come", " find", " give", " take",
    " life", " things", " years", " down", " part", " own", " point",
    " every", " different", " each", " might", " something", " these",
    " kind", " another", " both", " before", " last", " little",
]


class RichMockLMClient:
    """
    Deterministic mock LLM with a realistic 128-token vocabulary.

    Produces context-dependent distributions via SHA-256 hashing, giving
    varied but perfectly reproducible token probabilities. Both encoder
    and decoder get identical distributions for the same context, which
    is the critical property for SlopLink.

    Swap with a real LLM by replacing this fixture — the interface is
    identical (get_token_distribution → list[TokenProb]).
    """

    def __init__(self, vocab: list[str] | None = None, seed: int = 42):
        self.vocab = vocab or RICH_VOCAB
        self.seed = seed

    def get_token_distribution(self, context: str) -> list[TokenProb]:
        """Deterministic distribution based on SHA-256 of seed + context."""
        # Hash context for deterministic but well-distributed randomness
        h = hashlib.sha256(f"{self.seed}:{context}".encode()).digest()

        # Generate raw weights from hash bytes (extend if vocab > 32)
        raw = []
        rounds = math.ceil(len(self.vocab) / 32)
        for r in range(rounds):
            block = hashlib.sha256(h + struct.pack(">I", r)).digest()
            for b in block:
                raw.append(b + 1)  # avoid zero
                if len(raw) >= len(self.vocab):
                    break

        raw = raw[: len(self.vocab)]

        # Apply Zipf-like base (earlier tokens more probable) + hash noise
        weights = []
        for i, r in enumerate(raw):
            base = 1.0 / (i + 1) ** 0.6  # Gentle Zipf slope
            noise = r / 256.0
            weights.append(base * (0.5 + noise))

        total = sum(weights)
        result = [
            TokenProb(token=self.vocab[i], prob=weights[i] / total)
            for i in range(len(self.vocab))
        ]

        result.sort(key=lambda x: (-x.prob, x.token))
        return result

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Real LLM setup (opt-in)
# ---------------------------------------------------------------------------

USE_REAL_LLM = os.environ.get("SLOPLINK_USE_REAL_LLM", "").strip() not in ("", "0")

MODEL_URL = (
    "https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF"
    "/resolve/main/SmolLM2-135M-Instruct-Q8_0.gguf"
)
MODEL_FILENAME = "SmolLM2-135M-Instruct-Q8_0.gguf"
CACHE_DIR = os.path.expanduser("~/.cache/slopcrypt/models")


def _download_model(url: str, dest: str) -> None:
    """Download a GGUF model file with progress."""
    import httpx

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp_path = dest + ".downloading"
    print(f"Downloading {url} -> {dest}", file=sys.stderr)

    with httpx.stream("GET", url, follow_redirects=True, timeout=300) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        with open(tmp_path, "wb") as f:
            for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r  {downloaded // (1024*1024)}MB / {total // (1024*1024)}MB ({pct}%)",
                          end="", file=sys.stderr)
    print(file=sys.stderr)
    os.rename(tmp_path, dest)


def _get_real_client():
    """Create a real LLM client, or None if unavailable."""
    try:
        from slopcrypt.lm_client import LlamaCppClient
    except ImportError:
        return None

    env_path = os.environ.get("SLOPLINK_TEST_MODEL")
    if env_path and os.path.exists(env_path):
        model_path = env_path
    else:
        cached = os.path.join(CACHE_DIR, MODEL_FILENAME)
        if os.path.exists(cached):
            model_path = cached
        else:
            try:
                _download_model(MODEL_URL, cached)
                model_path = cached
            except Exception as e:
                print(f"Model download failed: {e}", file=sys.stderr)
                return None

    return LlamaCppClient(model_path=model_path, n_ctx=2048, top_k=40, verbose=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def llm_client():
    """
    LLM client fixture.

    Default: RichMockLMClient (fast, deterministic, no deps).
    Set SLOPLINK_USE_REAL_LLM=1 for SmolLM2 (slow, needs llama-cpp-python).
    """
    if USE_REAL_LLM:
        client = _get_real_client()
        if client is None:
            pytest.skip("Real LLM requested but unavailable (install llama-cpp-python)")
        yield client
        client.close()
    else:
        yield RichMockLMClient()


@pytest.fixture
def secret():
    """Generate a test secret with small preamble/suffix for speed."""
    return generate_secret(
        k=16,
        preamble_tokens=2,
        suffix_tokens=1,
        entropy_threshold=0.0,
    )


# ---------------------------------------------------------------------------
# Codec tests
# ---------------------------------------------------------------------------


class TestEncodeDecode:
    """Test the full encode/decode pipeline through SlopLink's codec."""

    def test_roundtrip_short_message(self, llm_client, secret):
        """Encode and decode a short text message."""
        message = b"Hello!"
        prompt = DEFAULT_SEED_PROMPT

        cover = encode_message(message, secret, llm_client, prompt=prompt)

        assert len(cover) > len(prompt)
        assert cover.startswith(prompt)

        decoded = decode_message(cover, secret, llm_client, prompt=prompt)
        assert decoded == message

    def test_roundtrip_binary_data(self, llm_client, secret):
        """Encode and decode raw binary bytes."""
        message = bytes(range(32))
        prompt = "Let me tell you about"

        cover = encode_message(message, secret, llm_client, prompt=prompt)
        decoded = decode_message(cover, secret, llm_client, prompt=prompt)
        assert decoded == message

    def test_roundtrip_with_role_prompt(self, llm_client, secret):
        """Encode with a role-specific system prompt, decode with the same."""
        message = b"Covert data"
        prompt = "Hey there"

        user_secret = dict(secret)
        user_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["user"]
        cover = encode_message(message, user_secret, llm_client, prompt=prompt)

        decoded = decode_message(cover, user_secret, llm_client, prompt=prompt)
        assert decoded == message

    def test_wrong_role_prompt_fails(self, llm_client, secret):
        """Decoding with the wrong role's system prompt should fail."""
        message = b"Secret"
        prompt = DEFAULT_SEED_PROMPT

        user_secret = dict(secret)
        user_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["user"]
        cover = encode_message(message, user_secret, llm_client, prompt=prompt)

        wrong_secret = dict(secret)
        wrong_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["assistant"]

        with pytest.raises((ValueError, RuntimeError)):
            decode_message(cover, wrong_secret, llm_client, prompt=prompt)

    def test_cover_text_is_printable(self, llm_client, secret):
        """Verify cover text contains printable, word-like content."""
        message = b"test"
        prompt = "So I was thinking about"

        cover = encode_message(message, secret, llm_client, prompt=prompt)
        generated = cover[len(prompt):]

        printable_ratio = sum(
            c.isprintable() or c.isspace() for c in generated
        ) / max(len(generated), 1)
        assert printable_ratio > 0.8, (
            f"Cover text is {printable_ratio:.0%} printable: {generated[:200]}"
        )

    def test_empty_message(self, llm_client, secret):
        """Encoding and decoding an empty message should roundtrip."""
        cover = encode_message(b"", secret, llm_client, prompt="Hello")
        decoded = decode_message(cover, secret, llm_client, prompt="Hello")
        assert decoded == b""


# ---------------------------------------------------------------------------
# Decoy tests
# ---------------------------------------------------------------------------


class TestDecoy:
    """Test decoy (cover traffic) generation."""

    def test_generate_slop_produces_text(self, llm_client, secret):
        """Decoy slop should be non-empty text."""
        slop = generate_slop(
            client=llm_client,
            prompt="Hey, what do you think about",
            system_prompt=DEFAULT_ROLE_PROMPTS["user"],
            k=secret["k"],
            num_tokens=30,
        )
        assert len(slop) > 0
        assert isinstance(slop, str)

    def test_decoy_not_decodable(self, llm_client, secret):
        """A decoy message must NOT decode as a real packet."""
        prompt = DEFAULT_SEED_PROMPT

        slop = generate_slop(
            client=llm_client,
            prompt=prompt,
            system_prompt=DEFAULT_ROLE_PROMPTS["user"],
            k=secret["k"],
            num_tokens=50,
        )

        with pytest.raises((ValueError, RuntimeError)):
            decode_message(prompt + slop, secret, llm_client, prompt=prompt)

    def test_slop_is_deterministic(self, llm_client, secret):
        """Same prompt + same client state → same slop (for mock client)."""
        if USE_REAL_LLM:
            pytest.skip("Determinism not guaranteed with real LLM")

        args = dict(
            client=llm_client,
            prompt="What's new?",
            system_prompt="Be casual.",
            k=secret["k"],
            num_tokens=20,
            temperature=0.0001,  # Near-greedy for determinism
        )
        slop1 = generate_slop(**args)
        slop2 = generate_slop(**args)
        assert slop1 == slop2


# ---------------------------------------------------------------------------
# Context continuity tests
# ---------------------------------------------------------------------------


class TestContextContinuity:
    """Test that conversation context chaining works across messages."""

    def test_sequential_messages(self, llm_client, secret):
        """
        Encode two messages in sequence, each using the previous message
        as its LLM prompt context. Both should decode correctly.
        """
        seed = "Hello there"
        ctx_sender = ConversationContext(window_size=1, seed_prompt=seed)
        ctx_receiver = ConversationContext(window_size=1, seed_prompt=seed)

        sys_prompt = DEFAULT_ROLE_PROMPTS["user"]
        secret_copy = dict(secret)
        secret_copy["system_prompt"] = sys_prompt

        # --- Message 1 ---
        msg1 = b"First"
        prompt1 = ctx_sender.get_prompt()
        assert prompt1 == ctx_receiver.get_prompt()

        cover1 = encode_message(msg1, secret_copy, llm_client, prompt=prompt1)
        tokens1 = cover1[len(prompt1):]

        recv_cover1 = ctx_receiver.get_prompt() + tokens1
        decoded1 = decode_message(recv_cover1, secret_copy, llm_client, prompt=ctx_receiver.get_prompt())
        assert decoded1 == msg1

        ctx_sender.add_message(tokens1)
        ctx_receiver.add_message(tokens1)

        # --- Message 2 (context = message 1's tokens) ---
        msg2 = b"Second"
        prompt2 = ctx_sender.get_prompt()
        assert prompt2 == ctx_receiver.get_prompt()
        assert prompt2 == tokens1

        cover2 = encode_message(msg2, secret_copy, llm_client, prompt=prompt2)
        tokens2 = cover2[len(prompt2):]

        recv_cover2 = ctx_receiver.get_prompt() + tokens2
        decoded2 = decode_message(recv_cover2, secret_copy, llm_client, prompt=ctx_receiver.get_prompt())
        assert decoded2 == msg2

    def test_decoy_then_real_message(self, llm_client, secret):
        """
        Send a decoy, then a real message. The real message should decode
        correctly even though the context now includes the decoy.
        """
        ctx_a = ConversationContext(window_size=1, seed_prompt="Hi")
        ctx_b = ConversationContext(window_size=1, seed_prompt="Hi")

        sys_prompt = DEFAULT_ROLE_PROMPTS["user"]

        # --- Decoy ---
        decoy = generate_slop(
            client=llm_client,
            prompt=ctx_a.get_prompt(),
            system_prompt=sys_prompt,
            k=secret["k"],
            num_tokens=20,
        )
        ctx_a.add_message(decoy)
        ctx_b.add_message(decoy)

        # --- Real message (context = the decoy) ---
        msg = b"After decoy"
        prompt = ctx_a.get_prompt()
        assert prompt == ctx_b.get_prompt()
        assert prompt == decoy

        real_secret = dict(secret)
        real_secret["system_prompt"] = sys_prompt
        cover = encode_message(msg, real_secret, llm_client, prompt=prompt)
        tokens = cover[len(prompt):]

        recv_cover = ctx_b.get_prompt() + tokens
        decoded = decode_message(recv_cover, real_secret, llm_client, prompt=ctx_b.get_prompt())
        assert decoded == msg


# ---------------------------------------------------------------------------
# Full peer-to-peer over Unix socket
# ---------------------------------------------------------------------------


class TestPeerToPeer:
    """End-to-end: two SlopLinkInterface instances over a Unix socket."""

    def test_unidirectional(self, llm_client, secret):
        """User sends a message, assistant receives it."""
        socket_path = tempfile.mktemp(suffix=".sloplink.sock")
        received: list[bytes] = []
        recv_event = threading.Event()

        try:
            server_transport = UnixSocketTransport(socket_path, listen=True)
            client_transport = UnixSocketTransport(socket_path, listen=False)

            def on_recv(data: bytes) -> None:
                received.append(data)
                recv_event.set()

            server = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=server_transport, role="user",
                enable_decoys=False, name="Server",
            )
            client = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=client_transport, role="assistant",
                enable_decoys=False, name="Client", on_receive=on_recv,
            )

            server.start()
            time.sleep(0.5)
            client.start()
            time.sleep(0.5)

            server.send_message(b"Hello peer!")
            assert recv_event.wait(timeout=30)
            assert received[0] == b"Hello peer!"
            assert len(server.context) == 1
            assert len(client.context) == 1

        finally:
            server.stop()
            client.stop()
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    def test_bidirectional(self, llm_client, secret):
        """Both peers send and receive messages."""
        socket_path = tempfile.mktemp(suffix=".sloplink.sock")
        server_received: list[bytes] = []
        client_received: list[bytes] = []
        server_evt = threading.Event()
        client_evt = threading.Event()

        try:
            server_transport = UnixSocketTransport(socket_path, listen=True)
            client_transport = UnixSocketTransport(socket_path, listen=False)

            server = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=server_transport, role="user",
                enable_decoys=False, name="Server",
                on_receive=lambda d: (server_received.append(d), server_evt.set()),
            )
            client = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=client_transport, role="assistant",
                enable_decoys=False, name="Client",
                on_receive=lambda d: (client_received.append(d), client_evt.set()),
            )

            server.start()
            time.sleep(0.5)
            client.start()
            time.sleep(0.5)

            # User -> Assistant
            server.send_message(b"ping")
            assert client_evt.wait(timeout=30)
            assert client_received[0] == b"ping"

            time.sleep(0.5)

            # Assistant -> User
            client.send_message(b"pong")
            assert server_evt.wait(timeout=30)
            assert server_received[0] == b"pong"

            assert len(server.context) == 2
            assert len(client.context) == 2

        finally:
            server.stop()
            client.stop()
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    def test_multiple_messages_in_sequence(self, llm_client, secret):
        """Send 3 messages in sequence, all decode correctly."""
        socket_path = tempfile.mktemp(suffix=".sloplink.sock")
        received: list[bytes] = []
        events = [threading.Event() for _ in range(3)]

        try:
            server_transport = UnixSocketTransport(socket_path, listen=True)
            client_transport = UnixSocketTransport(socket_path, listen=False)

            def on_recv(data: bytes) -> None:
                idx = len(received)
                received.append(data)
                if idx < len(events):
                    events[idx].set()

            server = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=server_transport, role="user",
                enable_decoys=False, name="Server",
            )
            client = SlopLinkInterface(
                owner=None, secret=secret, client=llm_client,
                transport=client_transport, role="assistant",
                enable_decoys=False, name="Client", on_receive=on_recv,
            )

            server.start()
            time.sleep(0.5)
            client.start()
            time.sleep(0.5)

            messages = [b"one", b"two", b"three"]
            for i, msg in enumerate(messages):
                server.send_message(msg)
                assert events[i].wait(timeout=30), f"Timed out on message {i+1}"
                assert received[i] == msg
                time.sleep(0.3)

            assert len(server.context) == 3
            assert len(client.context) == 3

        finally:
            server.stop()
            client.stop()
            if os.path.exists(socket_path):
                os.unlink(socket_path)
