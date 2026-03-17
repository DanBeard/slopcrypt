"""
SlopLink - Steganographic Reticulum Interface over Chat

Hides Reticulum network packets inside AI-generated "slop" text,
transmitted over chat platforms (IRC, Unix sockets, etc.).

Two peers exchange messages that look like a casual AI conversation,
but actually carry encrypted Reticulum traffic. Decoy messages are
injected at random intervals for plausible deniability.

Architecture:
    Reticulum Transport
        -> SlopLinkInterface (custom RNS Interface)
            -> SlopCrypt Codec (encode packets into slop)
                -> ChatTransport (send/receive text over chat)

Usage:
    # Start a peer (standalone, no RNS needed)
    python -m slopcrypt.sloplink peer --role user --secret my.secret --mock \\
        --transport irc --irc-server irc.libera.chat --irc-channel "#test"

    # Or as a Reticulum interface (requires RNS)
    python -m slopcrypt.sloplink rns --role user --secret my.secret --mock \\
        --transport irc --irc-server irc.libera.chat --irc-channel "#test"
"""

from slopcrypt.sloplink.context import ConversationContext
from slopcrypt.sloplink.decoy import DecoyManager
from slopcrypt.sloplink.interface import SlopLinkInterface
from slopcrypt.sloplink.transport import (
    ChatTransport,
    IRCTransport,
    UnixSocketTransport,
)

__all__ = [
    "ChatTransport",
    "ConversationContext",
    "DecoyManager",
    "IRCTransport",
    "SlopLinkInterface",
    "UnixSocketTransport",
]
