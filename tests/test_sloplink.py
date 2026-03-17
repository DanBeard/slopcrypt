"""
Tests for SlopLink - Steganographic chat transport.

Tests the full encode/decode pipeline through the SlopLink interface
using mock LLM clients and a local socket transport.
"""

import os
import tempfile
import threading
import time

import pytest

from slopcrypt.lm_client import MockLMClient
from slopcrypt.secret import generate_secret
from slopcrypt.sloplink.context import ConversationContext
from slopcrypt.sloplink.decoy import generate_slop
from slopcrypt.sloplink.interface import (
    DEFAULT_ROLE_PROMPTS,
    DEFAULT_SEED_PROMPT,
    SlopLinkInterface,
)
from slopcrypt.sloplink.transport import UnixSocketTransport


@pytest.fixture
def secret():
    """Generate a test secret."""
    return generate_secret(k=16, preamble_tokens=2, suffix_tokens=1)


@pytest.fixture
def mock_client():
    """Create a mock LLM client."""
    return MockLMClient(vocab_size=32)


class TestConversationContext:
    def test_empty_context_returns_seed(self):
        ctx = ConversationContext(seed_prompt="Hello!")
        assert ctx.get_prompt() == "Hello!"

    def test_single_message(self):
        ctx = ConversationContext(window_size=1)
        ctx.add_message("First message")
        assert ctx.get_prompt() == "First message"

    def test_window_size_1(self):
        ctx = ConversationContext(window_size=1)
        ctx.add_message("First")
        ctx.add_message("Second")
        ctx.add_message("Third")
        assert ctx.get_prompt() == "Third"

    def test_window_size_2(self):
        ctx = ConversationContext(window_size=2)
        ctx.add_message("First")
        ctx.add_message("Second")
        ctx.add_message("Third")
        assert ctx.get_prompt() == "Second\n\nThird"

    def test_clear(self):
        ctx = ConversationContext(seed_prompt="seed")
        ctx.add_message("msg")
        ctx.clear()
        assert ctx.get_prompt() == "seed"
        assert len(ctx) == 0


class TestDecoyGeneration:
    def test_generate_slop_produces_text(self, mock_client):
        slop = generate_slop(
            client=mock_client,
            prompt="Hello there",
            k=16,
            num_tokens=10,
        )
        assert len(slop) > 0
        assert isinstance(slop, str)

    def test_generate_slop_with_system_prompt(self, mock_client):
        slop = generate_slop(
            client=mock_client,
            prompt="Test prompt",
            system_prompt="Be casual.",
            k=16,
            num_tokens=10,
        )
        assert len(slop) > 0


class TestSlopLinkCodec:
    """Test encode/decode through the SlopLink interface."""

    def test_encode_decode_roundtrip(self, secret, mock_client):
        """Test that a message can be encoded and decoded through SlopLink."""
        # Create two interfaces sharing the same secret/client but no transport
        # We'll test the codec directly

        from slopcrypt.secret import decode_message, encode_message
        from slopcrypt.sloplink.interface import DEFAULT_SEED_PROMPT

        prompt = DEFAULT_SEED_PROMPT
        message = b"Hello SlopLink!"

        # Encode as "user" role
        user_secret = dict(secret)
        user_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["user"]
        cover = encode_message(message, user_secret, mock_client, prompt=prompt)

        # Decode as "assistant" role (but using user's system prompt since
        # that's what was used for encoding)
        decoded = decode_message(cover, user_secret, mock_client, prompt=prompt)
        assert decoded == message

    def test_role_prompt_mismatch_fails(self, secret, mock_client):
        """Using wrong role's system prompt should fail to decode."""
        from slopcrypt.secret import decode_message, encode_message
        from slopcrypt.sloplink.interface import DEFAULT_SEED_PROMPT

        prompt = DEFAULT_SEED_PROMPT
        message = b"Secret data"

        # Encode with user role prompt
        user_secret = dict(secret)
        user_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["user"]
        cover = encode_message(message, user_secret, mock_client, prompt=prompt)

        # Try to decode with WRONG (assistant) role prompt
        wrong_secret = dict(secret)
        wrong_secret["system_prompt"] = DEFAULT_ROLE_PROMPTS["assistant"]

        with pytest.raises((ValueError, RuntimeError)):
            decode_message(cover, wrong_secret, mock_client, prompt=prompt)


class TestSlopLinkInterface:
    """Test the full SlopLink interface with socket transport."""

    def test_interface_creation(self, secret, mock_client):
        """Test that interface can be created in standalone mode."""
        transport = UnixSocketTransport("/tmp/test_sloplink.sock", listen=True)
        iface = SlopLinkInterface(
            owner=None,
            secret=secret,
            client=mock_client,
            transport=transport,
            role="user",
            enable_decoys=False,
        )
        assert str(iface) == "SlopLinkInterface[SlopLink/user]"
        assert iface.peer_role == "assistant"

    def test_peer_to_peer_communication(self, secret, mock_client):
        """Test full peer-to-peer message exchange over socket."""
        socket_path = tempfile.mktemp(suffix=".sock")
        received = []
        recv_event = threading.Event()

        try:
            # Create server (user) and client (assistant) transports
            server_transport = UnixSocketTransport(socket_path, listen=True)
            client_transport = UnixSocketTransport(socket_path, listen=False)

            def on_recv(data: bytes):
                received.append(data)
                recv_event.set()

            server_iface = SlopLinkInterface(
                owner=None,
                secret=secret,
                client=mock_client,
                transport=server_transport,
                role="user",
                enable_decoys=False,
                name="Server",
            )

            client_iface = SlopLinkInterface(
                owner=None,
                secret=secret,
                client=mock_client,
                transport=client_transport,
                role="assistant",
                enable_decoys=False,
                name="Client",
                on_receive=on_recv,
            )

            # Start server first, then client
            server_iface.start()
            time.sleep(0.5)
            client_iface.start()
            time.sleep(0.5)

            # Send a message from user to assistant
            test_msg = b"Hello from user!"
            server_iface.send_message(test_msg)

            # Wait for receipt
            assert recv_event.wait(timeout=30), "Timed out waiting for message"
            assert len(received) > 0
            assert received[0] == test_msg

        finally:
            server_iface.stop()
            client_iface.stop()
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    def test_context_stays_in_sync(self, secret, mock_client):
        """Test that both peers maintain synchronized conversation context."""
        socket_path = tempfile.mktemp(suffix=".sock")
        received = []
        recv_event = threading.Event()

        try:
            server_transport = UnixSocketTransport(socket_path, listen=True)
            client_transport = UnixSocketTransport(socket_path, listen=False)

            def on_recv(data: bytes):
                received.append(data)
                recv_event.set()

            server_iface = SlopLinkInterface(
                owner=None,
                secret=secret,
                client=mock_client,
                transport=server_transport,
                role="user",
                enable_decoys=False,
            )

            client_iface = SlopLinkInterface(
                owner=None,
                secret=secret,
                client=mock_client,
                transport=client_transport,
                role="assistant",
                enable_decoys=False,
                on_receive=on_recv,
            )

            server_iface.start()
            time.sleep(0.5)
            client_iface.start()
            time.sleep(0.5)

            # Send message
            server_iface.send_message(b"Test sync")
            assert recv_event.wait(timeout=30)

            # Both should have 1 message in context
            time.sleep(0.5)
            assert len(server_iface.context) == 1
            assert len(client_iface.context) == 1

        finally:
            server_iface.stop()
            client_iface.stop()
            if os.path.exists(socket_path):
                os.unlink(socket_path)
