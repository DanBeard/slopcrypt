"""
SlopLink CLI - Run a steganographic chat peer.

Usage:
    # Peer mode with Unix socket (testing)
    python -m slopcrypt.sloplink peer --role user --secret my.secret --mock \
        --transport socket --socket-path /tmp/sloplink.sock --listen

    # Peer mode with IRC
    python -m slopcrypt.sloplink peer --role user --secret my.secret --mock \
        --transport irc --irc-server irc.libera.chat --irc-channel "#test" --irc-nick bot1

    # Interactive mode (stdin/stdout, for testing codec)
    python -m slopcrypt.sloplink interactive --role user --secret my.secret --mock

    # RNS interface mode (requires Reticulum)
    python -m slopcrypt.sloplink rns --role user --secret my.secret --mock \
        --transport irc --irc-server irc.libera.chat --irc-channel "#test" --irc-nick bot1
"""

from __future__ import annotations

import argparse
import getpass
import signal
import sys
import threading
import time

from slopcrypt.lm_client import DEFAULT_MODEL_PATH
from slopcrypt.secret import load_secret
from slopcrypt.sloplink.interface import SlopLinkInterface
from slopcrypt.sloplink.transport import IRCTransport, UnixSocketTransport


def create_transport(args) -> IRCTransport | UnixSocketTransport:
    """Create a chat transport from CLI args."""
    if args.transport == "irc":
        if not args.irc_server:
            print("--irc-server required for IRC transport", file=sys.stderr)
            sys.exit(1)
        if not args.irc_channel:
            print("--irc-channel required for IRC transport", file=sys.stderr)
            sys.exit(1)
        nick = args.irc_nick or f"sloplink_{args.role}"
        return IRCTransport(
            server=args.irc_server,
            channel=args.irc_channel,
            nick=nick,
            port=args.irc_port,
            use_ssl=args.irc_ssl,
        )
    elif args.transport == "socket":
        socket_path = args.socket_path or "/tmp/sloplink.sock"
        return UnixSocketTransport(
            socket_path=socket_path,
            listen=args.listen,
        )
    else:
        print(f"Unknown transport: {args.transport}", file=sys.stderr)
        sys.exit(1)


def create_client(args):
    """Create an LLM client from CLI args."""
    if args.mock:
        from slopcrypt.lm_client import MockLMClient
        return MockLMClient(vocab_size=max(32, 16))
    elif getattr(args, "mlx", False):
        if not args.mlx_model:
            print("--mlx-model required", file=sys.stderr)
            sys.exit(1)
        from slopcrypt.lm_client import MLXClient
        return MLXClient(model_name=args.mlx_model, top_k=64)
    elif getattr(args, "lmstudio", False):
        if not args.model:
            print("--model required for LM Studio", file=sys.stderr)
            sys.exit(1)
        from slopcrypt.lm_client import LMClient, LMConfig
        config = LMConfig(host=args.host, model=args.model, top_logprobs=10)
        return LMClient(config)
    else:
        if not args.model_path:
            print("Model path required. Use --model-path, --mlx, --lmstudio, or --mock", file=sys.stderr)
            sys.exit(1)
        from slopcrypt.lm_client import LlamaCppClient
        return LlamaCppClient(model_path=args.model_path, top_k=64)


def get_password(args) -> str:
    """Get password from args or prompt."""
    if args.password:
        return args.password
    return getpass.getpass("Secret password: ")


def cmd_peer(args) -> None:
    """Run a SlopLink peer with a chat transport."""
    password = get_password(args)
    secret = load_secret(args.secret, password)
    client = create_client(args)
    transport = create_transport(args)

    interface = SlopLinkInterface(
        owner=None,
        secret=secret,
        client=client,
        transport=transport,
        role=args.role,
        context_window=args.context_window,
        decoy_interval=args.decoy_interval,
        enable_decoys=not args.no_decoys,
        name=args.name or "SlopLink",
    )

    # Print received packets to stdout
    def on_recv(data: bytes) -> None:
        try:
            text = data.decode("utf-8", errors="replace")
            print(f"\n[RECV] {text}")
            print("> ", end="", flush=True)
        except Exception:
            print(f"\n[RECV] ({len(data)} bytes)")
            print("> ", end="", flush=True)

    interface._on_receive_standalone = on_recv

    # Handle Ctrl+C
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        print("\n[SlopLink] Shutting down...", file=sys.stderr)
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    interface.start()
    print(f"[SlopLink] Peer '{args.role}' ready. Type messages to send (Ctrl+C to quit).")
    print("> ", end="", flush=True)

    # Input loop - read from stdin, encode and send
    def input_loop():
        while not stop_event.is_set():
            try:
                line = input()
                if line.strip():
                    interface.send_message(line.encode("utf-8"))
                    print("> ", end="", flush=True)
            except EOFError:
                stop_event.set()
                break

    input_thread = threading.Thread(target=input_loop, daemon=True)
    input_thread.start()

    stop_event.wait()
    interface.stop()

    if hasattr(client, "close"):
        client.close()


def cmd_interactive(args) -> None:
    """Interactive mode: encode/decode individual messages for testing."""
    password = get_password(args)
    secret = load_secret(args.secret, password)
    client = create_client(args)

    from slopcrypt.sloplink.context import ConversationContext
    from slopcrypt.sloplink.interface import DEFAULT_ROLE_PROMPTS, DEFAULT_SEED_PROMPT

    ctx = ConversationContext(
        window_size=args.context_window,
        seed_prompt=DEFAULT_SEED_PROMPT,
    )
    role_prompts = dict(DEFAULT_ROLE_PROMPTS)

    print(f"[SlopLink Interactive] Role: {args.role}")
    print("Commands:")
    print("  encode <text>  - Encode text into slop")
    print("  decode <slop>  - Decode slop back to text")
    print("  decoy          - Generate a decoy message")
    print("  context        - Show current conversation context")
    print("  quit           - Exit")
    print()

    while True:
        try:
            line = input(f"[{args.role}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        if line == "quit":
            break
        elif line == "context":
            prompt = ctx.get_prompt()
            print(f"Context ({len(ctx)} messages): {prompt[:200]}{'...' if len(prompt) > 200 else ''}")
        elif line == "decoy":
            from slopcrypt.sloplink.decoy import generate_slop
            prompt = ctx.get_prompt()
            sys_prompt = role_prompts.get(args.role, "")
            slop = generate_slop(client, prompt, sys_prompt, secret["k"])
            print(f"[DECOY] {slop}")
            ctx.add_message(slop)
        elif line.startswith("encode "):
            payload = line[7:].encode("utf-8")
            prompt = ctx.get_prompt()
            sys_prompt = role_prompts.get(args.role, "")

            secret_copy = dict(secret)
            secret_copy["system_prompt"] = sys_prompt

            from slopcrypt.secret import encode_message
            cover = encode_message(payload, secret_copy, client, prompt=prompt)

            # Strip prompt
            if cover.startswith(prompt):
                tokens_only = cover[len(prompt):]
            else:
                tokens_only = cover

            print(f"[SLOP] {tokens_only}")
            ctx.add_message(tokens_only)
        elif line.startswith("decode "):
            slop = line[7:]
            prompt = ctx.get_prompt()
            peer_role = "assistant" if args.role == "user" else "user"
            sys_prompt = role_prompts.get(peer_role, "")
            full_cover = prompt + slop

            secret_copy = dict(secret)
            secret_copy["system_prompt"] = sys_prompt

            from slopcrypt.secret import decode_message
            try:
                data = decode_message(full_cover, secret_copy, client, prompt=prompt)
                print(f"[DECODED] {data.decode('utf-8', errors='replace')}")
            except (ValueError, RuntimeError) as e:
                print(f"[DECODE FAILED] {e} (probably a decoy)")
            ctx.add_message(slop)
        else:
            print("Unknown command. Try: encode, decode, decoy, context, quit")

    if hasattr(client, "close"):
        client.close()


def cmd_rns(args) -> None:
    """Run as a Reticulum interface."""
    try:
        import RNS
    except ImportError:
        print("Reticulum (RNS) is required for this mode.", file=sys.stderr)
        print("Install with: pip install rns", file=sys.stderr)
        sys.exit(1)

    password = get_password(args)
    secret = load_secret(args.secret, password)
    client = create_client(args)
    transport = create_transport(args)

    # Initialize Reticulum
    reticulum = RNS.Reticulum()

    interface = SlopLinkInterface(
        owner=reticulum,
        secret=secret,
        client=client,
        transport=transport,
        role=args.role,
        context_window=args.context_window,
        decoy_interval=args.decoy_interval,
        enable_decoys=not args.no_decoys,
        name=args.name or "SlopLink",
    )

    # Register with Reticulum transport
    RNS.Transport.interfaces.append(interface)

    interface.start()

    print(f"[SlopLink] Reticulum interface '{args.name or 'SlopLink'}' active as '{args.role}'")
    print("[SlopLink] Press Ctrl+C to stop")

    stop_event = threading.Event()

    def signal_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    stop_event.wait()

    interface.stop()
    if hasattr(client, "close"):
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SlopLink - Steganographic chat transport for Reticulum",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments added to each subparser
    def add_common_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--secret", required=True, help="SlopCrypt secret file")
        p.add_argument("--password", help="Secret password (prompted if not provided)")
        p.add_argument(
            "--role", required=True, choices=["user", "assistant"],
            help="This peer's conversation role",
        )
        p.add_argument(
            "--context-window", type=int, default=1,
            help="Number of recent messages for prompt context (default: 1)",
        )
        p.add_argument("--name", help="Interface name (default: SlopLink)")

        # Model selection
        p.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to GGUF model")
        p.add_argument("--mock", action="store_true", help="Use mock LLM client (testing)")
        p.add_argument("--mlx", action="store_true", help="Use MLX (Apple Silicon)")
        p.add_argument("--mlx-model", help="MLX model name")
        p.add_argument("--lmstudio", action="store_true", help="Use LM Studio API")
        p.add_argument("--host", default="http://192.168.1.12:1234/v1", help="LM Studio URL")
        p.add_argument("--model", help="Model name for LM Studio")

    def add_transport_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--transport", required=True, choices=["irc", "socket"],
            help="Chat transport backend",
        )
        # IRC options
        p.add_argument("--irc-server", help="IRC server hostname")
        p.add_argument("--irc-channel", help="IRC channel (e.g., #sloplink)")
        p.add_argument("--irc-nick", help="IRC nickname")
        p.add_argument("--irc-port", type=int, default=6667, help="IRC port")
        p.add_argument("--irc-ssl", action="store_true", help="Use SSL for IRC")
        # Socket options
        p.add_argument("--socket-path", help="Unix socket path")
        p.add_argument("--listen", action="store_true", help="Listen mode (server)")
        # Decoy options
        p.add_argument(
            "--decoy-interval", type=float, default=120.0,
            help="Mean seconds between decoy messages (default: 120)",
        )
        p.add_argument(
            "--no-decoys", action="store_true",
            help="Disable decoy traffic generation",
        )

    # Subcommand: peer
    peer_parser = subparsers.add_parser("peer", help="Run as a standalone SlopLink peer")
    add_common_args(peer_parser)
    add_transport_args(peer_parser)

    # Subcommand: interactive
    int_parser = subparsers.add_parser("interactive", help="Interactive encode/decode testing")
    add_common_args(int_parser)

    # Subcommand: rns
    rns_parser = subparsers.add_parser("rns", help="Run as a Reticulum interface")
    add_common_args(rns_parser)
    add_transport_args(rns_parser)

    args = parser.parse_args()

    if args.command == "peer":
        cmd_peer(args)
    elif args.command == "interactive":
        cmd_interactive(args)
    elif args.command == "rns":
        cmd_rns(args)


if __name__ == "__main__":
    main()
