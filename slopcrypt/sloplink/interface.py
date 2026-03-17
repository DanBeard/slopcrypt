"""
SlopLink Interface - Steganographic chat transport for Reticulum.

Can operate in two modes:
1. As a Reticulum Interface (when RNS is installed)
2. Standalone peer mode (for testing or non-RNS use)

Packets are encoded via SlopCrypt into AI-generated text, sent over a
ChatTransport backend (IRC, Unix socket, etc.), and decoded on the other end.
"""

from __future__ import annotations

import sys
import threading
from typing import Callable

from slopcrypt.secret import decode_message, encode_message
from slopcrypt.sloplink.context import ConversationContext
from slopcrypt.sloplink.decoy import DecoyManager
from slopcrypt.sloplink.transport import ChatTransport

# Role-specific system prompts.
# These are prepended to the LLM context (hidden from output) so that
# the generated text has the right conversational style for each role.
# Both peers must use the same prompts (stored in shared config, not the secret)
# because the decoder needs identical token distributions.
DEFAULT_ROLE_PROMPTS = {
    "user": (
        "You are a casual internet user chatting with a friend. "
        "Be natural, curious, and conversational. Ask questions sometimes. "
        "Keep responses medium length."
    ),
    "assistant": (
        "You are a friendly person chatting online with a buddy. "
        "Be warm, helpful, and conversational. Share opinions sometimes. "
        "Keep responses medium length."
    ),
}

DEFAULT_SEED_PROMPT = (
    "Just thinking about random stuff today. What have you been up to?"
)

# Try to import RNS for interface base class. Falls back gracefully.
try:
    from RNS.Interfaces.Interface import Interface as RNSInterface

    HAS_RNS = True
except ImportError:
    RNSInterface = object
    HAS_RNS = False


class SlopLinkInterface(RNSInterface):
    """
    Steganographic Reticulum interface over chat platforms.

    Encodes RNS packets into AI-generated text via SlopCrypt and transmits
    them over a ChatTransport backend. Decoy messages are generated at
    random intervals for traffic analysis resistance.

    Both peers must share:
    - The same SlopCrypt secret (knock, K, payload key, etc.)
    - The same LLM model (identical weights/quantization)
    - The same role prompts
    - Their assigned roles (one "user", one "assistant")

    The conversation context (last N messages) serves as the LLM prompt,
    and since both peers see the same chat messages, they can independently
    reconstruct the same token distributions for encoding/decoding.
    """

    AUTOCONFIGURE_MTU = False

    def __init__(
        self,
        owner,
        secret: dict,
        client,
        transport: ChatTransport,
        role: str = "user",
        role_prompts: dict[str, str] | None = None,
        seed_prompt: str = DEFAULT_SEED_PROMPT,
        context_window: int = 1,
        decoy_interval: float = 120.0,
        enable_decoys: bool = True,
        hw_mtu: int = 150,
        name: str = "SlopLink",
        on_receive: Callable[[bytes], None] | None = None,
    ):
        """
        Args:
            owner: Reticulum instance (or None for standalone mode).
            secret: Decrypted SlopCrypt secret dict.
            client: LLM client for encoding/decoding.
            transport: Chat transport backend.
            role: This peer's role ("user" or "assistant").
            role_prompts: Role -> system prompt mapping. Uses defaults if None.
            seed_prompt: Default prompt when no conversation history exists.
            context_window: Number of recent messages for prompt context.
            decoy_interval: Mean seconds between decoy messages.
            enable_decoys: Whether to generate decoy traffic.
            hw_mtu: Hardware MTU in bytes (max payload per packet).
            name: Human-readable interface name.
            on_receive: Callback for received packets (standalone mode).
        """
        if HAS_RNS and owner is not None:
            super().__init__()

        self.name = name
        self.secret = secret
        self.client = client
        self.transport = transport
        self.role = role
        self.peer_role = "assistant" if role == "user" else "user"
        self.role_prompts = role_prompts or dict(DEFAULT_ROLE_PROMPTS)
        self._on_receive_standalone = on_receive

        self.context = ConversationContext(
            window_size=context_window,
            seed_prompt=seed_prompt,
        )

        self._encode_lock = threading.Lock()
        self._decode_lock = threading.Lock()

        # RNS interface flags
        if HAS_RNS and owner is not None:
            self.owner = owner
            self.IN = True
            self.OUT = True
            self.online = False
            self.bitrate = 100  # Very slow medium
            self.HW_MTU = hw_mtu
        else:
            self.owner = None
            self.online = False
            self.HW_MTU = hw_mtu

        self.rxb = 0
        self.txb = 0

        # Wire up transport receive callback
        self.transport.on_receive(self._on_transport_receive)

        # Decoy traffic manager
        self._decoy: DecoyManager | None = None
        if enable_decoys:
            self._decoy = DecoyManager(
                send_fn=self._send_decoy_text,
                client=self.client,
                get_prompt_fn=self.context.get_prompt,
                system_prompt=self.role_prompts.get(self.role, ""),
                k=self.secret["k"],
                mean_interval=decoy_interval,
                temperature=self.secret.get("temperature", 0.8),
            )

    def start(self) -> None:
        """Connect transport and start the interface."""
        self.transport.connect()
        self.online = True

        if self._decoy:
            self._decoy.start()

        print(f"[SlopLink] Interface '{self.name}' online as '{self.role}'", file=sys.stderr)

    def stop(self) -> None:
        """Shut down the interface."""
        self.online = False

        if self._decoy:
            self._decoy.stop()

        self.transport.disconnect()
        print(f"[SlopLink] Interface '{self.name}' offline", file=sys.stderr)

    def detach(self) -> None:
        """RNS interface detach hook."""
        self.stop()
        if HAS_RNS:
            import RNS
            if self in RNS.Transport.interfaces:
                RNS.Transport.interfaces.remove(self)

    # ------------------------------------------------------------------ #
    # Outbound: RNS packet -> SlopCrypt -> Chat
    # ------------------------------------------------------------------ #

    def process_outgoing(self, data: bytes) -> None:
        """
        Called by RNS Transport to send a packet.

        Encodes the packet into cover text via SlopCrypt and sends it
        over the chat transport.
        """
        if not self.online:
            return

        try:
            with self._encode_lock:
                slop_text = self._encode_packet(data)

            if slop_text:
                self.transport.send(slop_text)
                self.context.add_message(slop_text)
                self.txb += len(data)
        except Exception as e:
            print(f"[SlopLink] TX error: {e}", file=sys.stderr)

    def send_message(self, data: bytes) -> None:
        """Standalone mode: encode and send arbitrary bytes."""
        self.process_outgoing(data)

    def _encode_packet(self, data: bytes) -> str | None:
        """Encode a packet into cover text using SlopCrypt."""
        prompt = self.context.get_prompt()
        my_system_prompt = self.role_prompts.get(self.role, "")

        # Override the secret's system_prompt with our role-specific one
        secret_copy = dict(self.secret)
        secret_copy["system_prompt"] = my_system_prompt

        cover_text = encode_message(
            message=data,
            secret=secret_copy,
            client=self.client,
            prompt=prompt,
        )

        # Strip the prompt prefix - we only send the generated tokens.
        # The receiver reconstructs the prompt from shared conversation context.
        if cover_text.startswith(prompt):
            return cover_text[len(prompt):]
        return cover_text

    # ------------------------------------------------------------------ #
    # Inbound: Chat -> SlopCrypt -> RNS packet
    # ------------------------------------------------------------------ #

    def _on_transport_receive(self, text: str) -> None:
        """Called by the transport when a message arrives from the peer."""
        if not self.online:
            return

        try:
            with self._decode_lock:
                data = self._try_decode(text)

            if data is not None:
                # Successfully decoded a packet
                self.context.add_message(text)
                self.rxb += len(data)

                if self.owner is not None and HAS_RNS:
                    self.owner.inbound(data, self)
                elif self._on_receive_standalone:
                    self._on_receive_standalone(data)
            else:
                # Decode failed - this is a decoy message (or corrupted).
                # Add to context regardless, since the peer expects us to
                # track all messages in the conversation.
                self.context.add_message(text)

        except Exception as e:
            # Add to context even on error to stay in sync
            self.context.add_message(text)
            print(f"[SlopLink] RX error: {e}", file=sys.stderr)

    def _try_decode(self, text: str) -> bytes | None:
        """
        Attempt to decode a received message.

        Returns the decoded payload bytes, or None if the message
        doesn't contain a valid payload (i.e., it's a decoy).
        """
        prompt = self.context.get_prompt()
        peer_system_prompt = self.role_prompts.get(self.peer_role, "")

        # Reconstruct the full cover text (prompt + received tokens)
        full_cover = prompt + text

        secret_copy = dict(self.secret)
        secret_copy["system_prompt"] = peer_system_prompt

        try:
            data = decode_message(
                cover_text=full_cover,
                secret=secret_copy,
                client=self.client,
                prompt=prompt,
            )
            return data
        except (ValueError, RuntimeError):
            # Decode failed - not a payload-bearing message
            return None

    # ------------------------------------------------------------------ #
    # Decoy traffic
    # ------------------------------------------------------------------ #

    def _send_decoy_text(self, text: str) -> None:
        """Send a decoy message and add it to conversation context."""
        if self.online and self.transport.connected:
            self.transport.send(text)
            self.context.add_message(text)

    # ------------------------------------------------------------------ #
    # Display
    # ------------------------------------------------------------------ #

    def __str__(self) -> str:
        return f"SlopLinkInterface[{self.name}/{self.role}]"

    def __repr__(self) -> str:
        return (
            f"SlopLinkInterface(name={self.name!r}, role={self.role!r}, "
            f"online={self.online}, txb={self.txb}, rxb={self.rxb})"
        )
