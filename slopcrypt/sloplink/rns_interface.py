"""
SlopLink — Reticulum interface that hides packets in Markov-chain chat text.

This file is loaded by Reticulum from ~/.reticulum/interfaces/ at startup.
The `Interface` base class and `RNS` module are injected by Reticulum's
exec() loader — do NOT import them at the top level.

Requires: pip install slopcrypt markovify

Config example:
    [[SlopLink IRC]]
      type = SlopLinkInterface
      enabled = true
      role = user
      markov_model = /path/to/garden_irc.markov.json
      payload_key = base64-encoded-32-byte-key
      transport_type = irc
      irc_server = irc.libera.chat
      irc_port = 6667
      irc_channel = "#digital-garden-notes"
      irc_nick = gardenbot_a
      decoy_interval = 90
      no_decoys = false
"""

import base64
import os
import random
import secrets
import sys
import threading
import time

from slopcrypt.lm_client import MarkovClient
from slopcrypt.sloplink.codec import encode, decode
from slopcrypt.sloplink.transport import IRCTransport, UnixSocketTransport
from slopcrypt.utils import TokenProb

# Default knock sequence — shared between all SlopLink peers using the same model
DEFAULT_KNOCK = [4, 7, 2, 9, 14, 1]


def _create_transport(config):
    """Create a chat transport from config."""
    transport_type = config.get("transport_type", "irc").lower()
    if transport_type == "irc":
        server = config.get("irc_server")
        channel = config.get("irc_channel")
        if not server or not channel:
            raise ValueError("SlopLink IRC: irc_server and irc_channel required")
        nick = config.get("irc_nick", "sloplink_bot")
        port = int(config.get("irc_port", "6667"))
        use_ssl = config.get("irc_ssl", "false").lower() in ("true", "yes", "1")
        return IRCTransport(server=server, channel=channel, nick=nick, port=port, use_ssl=use_ssl)
    elif transport_type == "socket":
        path = config.get("socket_path", "/tmp/sloplink.sock")
        listen = config.get("socket_listen", "false").lower() in ("true", "yes", "1")
        return UnixSocketTransport(socket_path=path, listen=listen)
    else:
        raise ValueError(f"SlopLink: Unknown transport_type: {transport_type}")


class SlopLinkRNSInterface(Interface):
    """
    Reticulum interface using Markov chain steganography over chat.

    Encodes RNS packets into gardening-themed chat text using a trained
    Markov chain model. Decoy messages are generated at random intervals
    for plausible deniability.
    """

    AUTOCONFIGURE_MTU = False
    DEFAULT_IFAC_SIZE = 16

    def __init__(self, owner, configuration):
        super().__init__()

        c = configuration
        self.name = c.get("name", "SlopLink")

        # --- Markov model ---
        model_path = c.get("markov_model")
        if not model_path or not os.path.exists(model_path):
            raise ValueError(f"SlopLink: markov_model path required and must exist (got: {model_path})")
        RNS.log(f"SlopLink: loading Markov model from {model_path}", RNS.LOG_NOTICE)
        t0 = time.time()
        self.client = MarkovClient.from_file(model_path)
        t1 = time.time()
        RNS.log(f"SlopLink: model loaded in {t1-t0:.1f}s ({len(self.client._distributions)} states)", RNS.LOG_NOTICE)

        # --- Encryption key ---
        key_b64 = c.get("payload_key")
        if key_b64:
            self.payload_key = base64.b64decode(key_b64)
            if len(self.payload_key) != 32:
                raise ValueError("SlopLink: payload_key must be 32 bytes (base64 encoded)")
        else:
            # Auto-generate (both peers MUST use the same key — share via config)
            raise ValueError("SlopLink: payload_key required (base64-encoded 32-byte AES key)")

        self.knock = DEFAULT_KNOCK
        self.k = int(c.get("k", "16"))

        # --- Transport ---
        self.transport = _create_transport(c)

        # --- RNS interface flags ---
        self.owner = owner
        self.IN = True
        self.OUT = True
        self.online = False
        self.bitrate = 1000  # Markov is fast — don't throttle announces
        self.HW_MTU = int(c.get("hw_mtu", "500"))

        self._encode_lock = threading.Lock()

        # --- Wire up transport ---
        self.transport.on_receive(self._on_transport_receive)

        # --- Connect ---
        try:
            self.transport.connect()
            self.online = True
            RNS.log(f"SlopLink interface '{self.name}' online", RNS.LOG_NOTICE)
        except Exception as e:
            RNS.log(f"SlopLink transport connect failed: {e}", RNS.LOG_ERROR)
            raise

        # --- Decoy traffic ---
        no_decoys = c.get("no_decoys", "false").lower() in ("true", "yes", "1")
        self._decoy_interval = float(c.get("decoy_interval", "90"))
        self._decoy_stop = threading.Event()
        if not no_decoys:
            self._decoy_thread = threading.Thread(target=self._decoy_loop, daemon=True)
            self._decoy_thread.start()
        else:
            self._decoy_thread = None

    # ------------------------------------------------------------------ #
    # Outbound: RNS packet → Markov encode → IRC
    # ------------------------------------------------------------------ #

    def process_outgoing(self, data):
        """Called by RNS Transport to send a packet."""
        if not self.online:
            return
        try:
            with self._encode_lock:
                prompt = ""
                cover = encode(
                    data, self.client, prompt,
                    k=self.k, knock=self.knock, payload_key=self.payload_key,
                )

            self.transport.send(cover)
            self.txb += len(data)
            RNS.log(f"SlopLink TX: {len(data)}B → {len(cover)} chars", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"SlopLink TX error: {e}", RNS.LOG_ERROR)

    # ------------------------------------------------------------------ #
    # Inbound: IRC → Markov decode → RNS packet
    # ------------------------------------------------------------------ #

    def _on_transport_receive(self, text):
        """Called by transport when a chat message arrives.
        Dispatches to worker thread so IRC recv loop stays free for PINGs.
        """
        with open("/tmp/sloplink_debug.log", "a") as _f:
            _f.write(f"CALLBACK: {len(text)} chars, online={self.online}\n")
        if not self.online:
            return
        t = threading.Thread(target=self._process_incoming, args=(text,), daemon=True)
        t.start()

    def _process_incoming(self, text):
        """Decode a received message (runs in worker thread)."""
        try:
            self._slog(f"RX: trying decode ({len(text)} chars)")
            data = decode(
                text, self.client, "",
                k=self.k, knock=self.knock, payload_key=self.payload_key,
            )
            self.rxb += len(data)
            self._slog(f"RX: DECODED {len(data)}B from {len(text)} chars!")
            RNS.log(f"SlopLink RX: DECODED {len(data)}B", RNS.LOG_NOTICE)
            self.owner.inbound(data, self)

        except (ValueError, RuntimeError) as e:
            self._slog(f"RX: not a packet ({len(text)} chars): {e}")

        except Exception as e:
            import traceback
            self._slog(f"RX CRASH: {e}\n{traceback.format_exc()}")

    def _slog(self, msg):
        """Write to a clean sidecar log (avoids binary corruption from llama.cpp)."""
        try:
            with open("/tmp/sloplink_debug.log", "a") as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Decoy traffic
    # ------------------------------------------------------------------ #

    def _decoy_loop(self):
        """Generate decoy messages at random intervals."""
        while not self._decoy_stop.is_set():
            delay = random.expovariate(1.0 / self._decoy_interval)
            delay = max(15.0, min(delay, self._decoy_interval * 5))
            if self._decoy_stop.wait(timeout=delay):
                break
            if not self.online:
                continue
            try:
                prompt = ""
                # Generate natural text (no payload) by sampling from the Markov chain
                num_tokens = random.randint(8, 30)
                context = prompt
                tokens = []
                for _ in range(num_tokens):
                    dist = self.client.get_token_distribution(context)
                    if not dist:
                        break
                    # Weighted random sample
                    total = sum(t.prob for t in dist[:32])
                    r = random.random() * total
                    cumulative = 0.0
                    chosen = dist[0]
                    for t in dist[:32]:
                        cumulative += t.prob
                        if r < cumulative:
                            chosen = t
                            break
                    tokens.append(chosen.token)
                    context += chosen.token

                slop = "".join(tokens)
                if slop.strip():
                    self.transport.send(slop)
            except Exception as e:
                RNS.log(f"SlopLink decoy error: {e}", RNS.LOG_ERROR)

    def _random_prompt(self):
        """Pick a random gardening-ish prompt for encoding context."""
        prompts = [
            "My tomato plants are",
            "Does anyone know how to",
            "I just planted some new",
            "The weather has been really",
            "Has anyone tried growing",
            "I noticed my garden",
            "What kind of soil",
            "The best time to",
            "Any tips for keeping",
            "I was thinking about",
            "My raised beds need",
            "Looking for advice on",
            "Just finished watering the",
            "The compost pile is",
            "Spring planting season is",
        ]
        return random.choice(prompts)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def detach(self):
        self.online = False
        self._decoy_stop.set()
        self.transport.disconnect()
        RNS.log(f"SlopLink interface '{self.name}' detached", RNS.LOG_NOTICE)

    def __str__(self):
        return f"SlopLinkInterface[{self.name}]"


# Required by Reticulum's external interface loader
interface_class = SlopLinkRNSInterface
