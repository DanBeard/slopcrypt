# SlopLink: Steganographic Reticulum Interface Over Chat

SlopLink hides [Reticulum](https://reticulum.network) network packets inside
AI-generated text ("slop") and transmits them over ordinary chat platforms.
Two peers exchange messages that look like a casual conversation between
a person and an AI assistant, but every message actually carries encrypted
network traffic — or is a decoy that carries nothing at all.

```
┌─────────────────────────────────┐
│  Reticulum Transport            │  Standard RNS stack (optional)
├─────────────────────────────────┤
│  SlopLinkInterface              │  Custom RNS Interface
│  process_outgoing() / inbound() │
├─────────────────────────────────┤
│  SlopCrypt Codec                │  Arithmetic-coded steganography
│  encode_message / decode_message│
├─────────────────────────────────┤
│  ChatTransport (abstract)       │  Generic text send/receive
├──────────┬──────────┬───────────┤
│ IRC      │ Unix     │ Future:   │
│ Backend  │ Socket   │ Signal,   │
│          │ Backend  │ Matrix,   │
│          │          │ Discord   │
└──────────┴──────────┴───────────┘
```

## How It Works

### The Conversation Trick

SlopLink sets up two peers with asymmetric **conversation roles** — one plays
a "user" and the other plays an "assistant". Each role has its own LLM system
prompt that shapes the style of generated text:

- **User role**: casual, curious, asks questions
- **Assistant role**: friendly, helpful, shares opinions

The result is that intercepted traffic looks like someone chatting with an AI
(the most common type of text on the internet in 2026).

### Encoding a Packet

When Reticulum wants to send a packet through SlopLink:

1. **Build prompt** — The last message in the chat becomes the LLM prompt
   (configurable window, default 1). Both peers see the same chat, so they
   independently derive the same prompt.
2. **Encode** — SlopCrypt's arithmetic coder selects tokens from the LLM's
   probability distribution such that:
   - Each token choice encodes bits from the encrypted payload
   - Token selection is proportional to natural probability (statistically
     indistinguishable from normal LLM output)
3. **Strip prompt** — Only the generated tokens are sent over chat (the
   prompt is reconstructable from context).
4. **Send** — The ChatTransport delivers the text to the channel.

### Decoding a Packet

When a message arrives from the peer:

1. **Reconstruct prompt** — Same last-N-messages window as the encoder used.
2. **Prepend prompt** — Rebuild the full cover text.
3. **Decode** — SlopCrypt walks the token distributions, finds the knock
   sequence, extracts the encrypted payload.
4. **Deliver** — Pass decoded bytes to Reticulum (or the standalone callback).
5. **If decode fails** — The message was a decoy. Add it to context and move on.

### Decoy Traffic

Both peers independently generate **cover traffic** — pure LLM text with no
hidden payload — at random Poisson-distributed intervals. This prevents:

- **Timing analysis**: Real packets correlate with application activity;
  decoys add noise that masks these patterns.
- **Volume analysis**: Steady background chatter means bursts of real traffic
  don't stand out.
- **Plausible deniability**: If all messages look the same and some are
  genuinely just AI slop, you can't prove any specific message carries data.

### Context Continuity

Each message uses the previous message as its LLM prompt context. This means
the "conversation" naturally flows from one message to the next, building a
coherent (if meandering) dialogue. There's no hard cut between messages —
they read like a real back-and-forth.

## Threat Model

### What SlopLink Protects Against

- **Content inspection**: Messages are encrypted (AES-256-GCM) and then
  steganographically embedded. An observer sees only plausible LLM text.
- **Statistical detection**: Arithmetic coding selects tokens proportionally
  to their natural probability. The output distribution matches normal LLM
  generation.
- **Timing correlation**: Decoy messages add noise to traffic patterns.
- **Protocol fingerprinting**: There is no SlopLink protocol on the wire.
  It's just text in IRC/Signal/whatever.

### What SlopLink Does NOT Protect Against

- **Endpoint compromise**: If an attacker has the secret file and model,
  they can decode everything.
- **Model identification**: Someone who suspects SlopLink and knows which
  model you're using could test if messages match that model's distribution.
  Mitigated by using common models (everyone's text looks the same).
- **Behavioral analysis**: If two accounts only ever talk to each other in
  AI-sounding text, that's suspicious. Use in channels with other traffic.
- **Long-term traffic analysis**: Over very long periods, the pattern of
  real+decoy traffic might diverge from pure random. Tuning decoy parameters
  helps.

### Requirements for Security

1. **Both peers must use the exact same LLM** — same model, same weights,
   same quantization. Even minor differences will produce different token
   distributions and break decoding.
2. **Shared secret** — Contains the knock sequence, encryption key, K value,
   and role prompts. Distribute out-of-band.
3. **Shared role prompts** — Both peers must agree on the system prompts for
   each role. (Currently hardcoded defaults; future: store in secret.)

## Installation

```bash
# Core SlopLink (no LLM backend)
pip install slopcrypt

# With llama.cpp backend (recommended)
pip install slopcrypt[llama]

# With Reticulum support
pip install slopcrypt[rns]

# Everything
pip install slopcrypt[llama,rns]
```

## Quick Start

### 1. Generate a Shared Secret

```bash
python -m slopcrypt.secret generate-secret \
  -o sloplink.secret \
  --k 16 \
  --system-prompt "casual chat"
```

Distribute `sloplink.secret` and the password to both peers securely.

### 2. Start Peer A (User Role)

```bash
# Over IRC
python -m slopcrypt.sloplink peer \
  --role user \
  --secret sloplink.secret \
  --transport irc \
  --irc-server irc.libera.chat \
  --irc-channel "#random-chat-12345" \
  --irc-nick alice_ai \
  --model-path SmolLM2-135M-Instruct-Q8_0.gguf

# Or over Unix socket (local testing)
python -m slopcrypt.sloplink peer \
  --role user \
  --secret sloplink.secret \
  --transport socket \
  --socket-path /tmp/sloplink.sock \
  --listen \
  --mock  # use mock LLM for testing
```

### 3. Start Peer B (Assistant Role)

```bash
python -m slopcrypt.sloplink peer \
  --role assistant \
  --secret sloplink.secret \
  --transport irc \
  --irc-server irc.libera.chat \
  --irc-channel "#random-chat-12345" \
  --irc-nick bob_helper \
  --model-path SmolLM2-135M-Instruct-Q8_0.gguf
```

Now type messages in either terminal — they're encoded into slop, sent over
IRC, and decoded on the other end. Decoy messages flow automatically.

### 4. As a Reticulum Interface

```bash
python -m slopcrypt.sloplink rns \
  --role user \
  --secret sloplink.secret \
  --transport irc \
  --irc-server irc.libera.chat \
  --irc-channel "#random-chat-12345" \
  --irc-nick alice_ai \
  --model-path SmolLM2-135M-Instruct-Q8_0.gguf
```

This registers SlopLink as a Reticulum interface. Any RNS application
(LXMF, NomadNet, etc.) can now route traffic over the chat channel.

### 5. Interactive Testing Mode

```bash
python -m slopcrypt.sloplink interactive \
  --role user \
  --secret sloplink.secret \
  --mock

# Commands:
#   encode <text>  — Encode text into slop
#   decode <slop>  — Decode slop back to text
#   decoy          — Generate a decoy message
#   context        — Show conversation context
```

## CLI Reference

### `python -m slopcrypt.sloplink peer`

Run a standalone SlopLink peer.

| Flag | Default | Description |
|------|---------|-------------|
| `--role` | required | `user` or `assistant` |
| `--secret` | required | Path to SlopCrypt secret file |
| `--transport` | required | `irc` or `socket` |
| `--context-window` | `1` | Messages of context for LLM prompt |
| `--decoy-interval` | `120` | Mean seconds between decoy messages |
| `--no-decoys` | false | Disable decoy traffic |
| `--mock` | false | Use mock LLM (testing only) |
| `--model-path` | env `STEGO_MODEL_PATH` | Path to GGUF model |
| `--lmstudio` | false | Use LM Studio API |
| `--mlx` | false | Use MLX (Apple Silicon) |

#### IRC Transport Options

| Flag | Default | Description |
|------|---------|-------------|
| `--irc-server` | required | IRC server hostname |
| `--irc-channel` | required | Channel name (e.g., `#test`) |
| `--irc-nick` | `sloplink_<role>` | Bot nickname |
| `--irc-port` | `6667` | Server port |
| `--irc-ssl` | false | Use TLS |

#### Socket Transport Options

| Flag | Default | Description |
|------|---------|-------------|
| `--socket-path` | `/tmp/sloplink.sock` | Unix socket path |
| `--listen` | false | Listen (server) vs connect (client) |

## Adding a New Transport

Implement `ChatTransport`:

```python
from slopcrypt.sloplink.transport import ChatTransport

class SignalTransport(ChatTransport):
    def send(self, text: str) -> None:
        """Send text to the peer."""
        ...

    def on_receive(self, callback) -> None:
        """Register callback for incoming messages."""
        self._callback = callback

    def connect(self) -> None:
        """Connect to Signal."""
        ...

    def disconnect(self) -> None:
        """Disconnect."""
        ...

    @property
    def connected(self) -> bool:
        return self._connected
```

Then pass it to `SlopLinkInterface`:

```python
transport = SignalTransport(phone="+1234567890")
interface = SlopLinkInterface(
    owner=None,
    secret=secret,
    client=client,
    transport=transport,
    role="user",
)
interface.start()
```

The transport only needs to move strings — SlopLink handles all the
encoding, decoding, context tracking, and decoy generation.

## Performance Characteristics

| Metric | Approximate Value |
|--------|-------------------|
| Encoding speed | 10-100 tokens/sec (depends on model, hardware) |
| Payload per message | ~30-200 bytes (depends on MTU, K) |
| Bits per token | 4 (with K=16) |
| Overhead | ~28 bytes (AES-GCM nonce+tag) + compression header |
| Latency | 2-60 seconds per packet (model-dependent) |

SlopLink is designed for **low-bandwidth, high-latency** communication.
This is fine for Reticulum, which was built for exactly these conditions.
It's not suitable for streaming or real-time applications.

## Architecture Details

### Module Structure

```
slopcrypt/sloplink/
├── __init__.py        Package exports
├── __main__.py        CLI (peer, interactive, rns modes)
├── context.py         ConversationContext — rolling prompt window
├── decoy.py           DecoyManager — Poisson-distributed cover traffic
├── interface.py       SlopLinkInterface — core RNS interface
└── transport.py       ChatTransport ABC, IRC, Unix socket backends
```

### Conversation Context Synchronization

Both peers maintain an identical `ConversationContext` — a list of all
messages exchanged on the channel. When encoding, the sender builds the
LLM prompt from the last N messages. When decoding, the receiver builds
the same prompt from the same messages (they're on the same channel).

This works because:
1. Chat channels deliver messages to all participants in order
2. Both peers add every message (real or decoy) to their context
3. The prompt is derived deterministically from the message history

If context drifts (dropped message, network hiccup), decoding fails for
that message. Reticulum handles retransmission at a higher layer.

### Role System

The asymmetric role system is what makes the conversation look natural:

| Role | System Prompt Style | Token Distribution |
|------|--------------------|--------------------|
| user | Curious, casual, asks questions | Tends toward question patterns |
| assistant | Friendly, helpful, shares info | Tends toward answer patterns |

Both peers know both role prompts. The encoder uses its own role's prompt;
the decoder uses the sender's role prompt. This ensures identical token
distributions on both sides.

## Future Work

- **Signal transport**: Via signal-cli or linked device API
- **Matrix transport**: Via matrix-nio
- **Discord transport**: Via discord.py
- **Multi-party channels**: More than 2 peers, role rotation
- **Adaptive decoy timing**: Learn from network patterns
- **Model negotiation**: Agree on model via initial handshake
- **Fragmentation**: Split large packets across multiple messages transparently
- **Store in secret**: Move role prompts into the shared secret blob
