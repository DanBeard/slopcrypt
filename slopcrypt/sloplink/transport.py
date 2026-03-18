"""
Chat transport backends for SlopLink.

Each transport moves text strings between peers over a specific chat medium.
The interface is intentionally minimal: send text, receive text via callback.
"""

from __future__ import annotations

import os
import re
import select
import socket
import sys
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable


class ChatTransport(ABC):
    """Abstract base class for chat transport backends."""

    @abstractmethod
    def send(self, text: str) -> None:
        """Send a text message to the peer(s)."""

    @abstractmethod
    def on_receive(self, callback: Callable[[str], None]) -> None:
        """Register a callback for incoming messages."""

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the chat medium."""

    @abstractmethod
    def disconnect(self) -> None:
        """Cleanly disconnect from the chat medium."""

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Whether the transport is currently connected."""


class UnixSocketTransport(ChatTransport):
    """
    Transport over Unix domain sockets for local testing.

    One peer runs as server (listen=True), the other as client.
    Messages are newline-delimited text.
    """

    def __init__(self, socket_path: str, listen: bool = False):
        """
        Args:
            socket_path: Path for the Unix domain socket.
            listen: If True, listen for connections. If False, connect.
        """
        self.socket_path = socket_path
        self.listen = listen
        self._callback: Callable[[str], None] | None = None
        self._conn: socket.socket | None = None
        self._server: socket.socket | None = None
        self._running = False
        self._recv_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def on_receive(self, callback: Callable[[str], None]) -> None:
        self._callback = callback

    def connect(self) -> None:
        if self.listen:
            # Clean up stale socket
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(self.socket_path)
            self._server.listen(1)
            self._server.settimeout(1.0)
            self._running = True
            self._recv_thread = threading.Thread(
                target=self._server_loop, daemon=True
            )
            self._recv_thread.start()
        else:
            self._conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._conn.connect(self.socket_path)
            self._running = True
            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True
            )
            self._recv_thread.start()

    def _server_loop(self) -> None:
        """Accept a connection then start receiving."""
        while self._running:
            try:
                conn, _ = self._server.accept()
                self._conn = conn
                self._recv_loop()
            except socket.timeout:
                continue
            except OSError:
                break

    def _recv_loop(self) -> None:
        """Read newline-delimited messages from the connection."""
        buf = b""
        conn = self._conn
        while self._running and conn:
            try:
                ready, _, _ = select.select([conn], [], [], 0.5)
                if not ready:
                    continue
                data = conn.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace")
                    if text and self._callback:
                        self._callback(text)
            except OSError:
                break

    def send(self, text: str) -> None:
        with self._lock:
            if self._conn:
                # Escape newlines within the message for framing
                escaped = text.replace("\n", "\\n")
                self._conn.sendall((escaped + "\n").encode("utf-8"))

    def disconnect(self) -> None:
        self._running = False
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

    @property
    def connected(self) -> bool:
        return self._conn is not None and self._running


class IRCTransport(ChatTransport):
    """
    Transport over IRC.

    Sends and receives messages in an IRC channel. Long messages are
    split across multiple lines; the receiver buffers and reassembles
    consecutive messages from the same sender.
    """

    # Max bytes per PRIVMSG payload (conservative, accounts for header overhead)
    MAX_MSG_LEN = 400

    def __init__(
        self,
        server: str,
        channel: str,
        nick: str,
        port: int = 6667,
        use_ssl: bool = False,
        password: str | None = None,
        reassembly_timeout: float = 2.0,
    ):
        """
        Args:
            server: IRC server hostname.
            channel: Channel to join (e.g., "#sloplink").
            nick: Bot nickname.
            port: Server port.
            use_ssl: Use SSL/TLS.
            password: Server password (optional).
            reassembly_timeout: Seconds to wait for more fragments.
        """
        self.server = server
        self.channel = channel if channel.startswith("#") else f"#{channel}"
        self.nick = nick
        self.port = port
        self.use_ssl = use_ssl
        self.password = password
        self.reassembly_timeout = reassembly_timeout

        self._callback: Callable[[str], None] | None = None
        self._sock: socket.socket | None = None
        self._running = False
        self._recv_thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._joined = threading.Event()

        # Reassembly buffer: {nick: (fragments, last_time)}
        self._reassembly: dict[str, tuple[list[str], float]] = {}
        self._reassembly_lock = threading.Lock()

    def on_receive(self, callback: Callable[[str], None]) -> None:
        self._callback = callback

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            self._sock = ctx.wrap_socket(self._sock, server_hostname=self.server)

        self._sock.connect((self.server, self.port))
        self._running = True

        if self.password:
            self._irc_send(f"PASS {self.password}")
        self._irc_send(f"NICK {self.nick}")
        self._irc_send(f"USER {self.nick} 0 * :SlopLink Bot")

        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        # Wait for join confirmation (with timeout)
        self._joined.wait(timeout=30)

    def _irc_send(self, line: str) -> None:
        """Send a raw IRC line."""
        with self._lock:
            if self._sock:
                self._sock.sendall((line + "\r\n").encode("utf-8"))

    def _recv_loop(self) -> None:
        """Parse incoming IRC messages with auto-reconnect."""
        while self._running:
            buf = b""
            try:
                while self._running and self._sock:
                    ready, _, _ = select.select([self._sock], [], [], 0.5)
                    self._check_reassembly_timeout()
                    if not ready:
                        continue
                    data = self._sock.recv(4096)
                    if not data:
                        print("[SlopLink IRC] Connection closed by server", file=sys.stderr)
                        break
                    buf += data
                    while b"\r\n" in buf:
                        line, buf = buf.split(b"\r\n", 1)
                        self._handle_irc_line(line.decode("utf-8", errors="replace"))
            except OSError as e:
                print(f"[SlopLink IRC] Connection error: {e}", file=sys.stderr)

            if not self._running:
                break

            # Auto-reconnect
            print("[SlopLink IRC] Reconnecting in 10 seconds...", file=sys.stderr)
            self._joined.clear()
            time.sleep(10)
            try:
                if self._sock:
                    try:
                        self._sock.close()
                    except OSError:
                        pass
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.use_ssl:
                    import ssl
                    ctx = ssl.create_default_context()
                    self._sock = ctx.wrap_socket(self._sock, server_hostname=self.server)
                self._sock.connect((self.server, self.port))
                if self.password:
                    self._irc_send(f"PASS {self.password}")
                self._irc_send(f"NICK {self.nick}")
                self._irc_send(f"USER {self.nick} 0 * :SlopLink Bot")
                self._joined.wait(timeout=30)
                print("[SlopLink IRC] Reconnected successfully", file=sys.stderr)
            except Exception as e:
                print(f"[SlopLink IRC] Reconnect failed: {e}", file=sys.stderr)

    def _handle_irc_line(self, line: str) -> None:
        """Process a single IRC protocol line."""
        # Debug: log every non-trivial line
        if "PRIVMSG" in line or "PING" in line:
            print(f"[SlopLink IRC DBG] {line[:120]}", file=sys.stderr)

        # PING/PONG keepalive
        if line.startswith("PING"):
            self._irc_send("PONG" + line[4:])
            return

        # Parse IRC message
        prefix = ""
        if line.startswith(":"):
            prefix, line = line[1:].split(" ", 1)

        parts = line.split(" ", 2)
        command = parts[0] if parts else ""

        # Handle numeric replies
        if command == "001":
            # Welcome - now join channel
            self._irc_send(f"JOIN {self.channel}")
        elif command == "366":
            # End of NAMES list - join complete
            self._joined.set()
        elif command == "433":
            # Nick in use - append underscore
            self.nick += "_"
            self._irc_send(f"NICK {self.nick}")

        # Handle PRIVMSG
        elif command == "PRIVMSG" and len(parts) >= 3:
            target = parts[1]
            message = parts[2]
            if message.startswith(":"):
                message = message[1:]

            # Extract sender nick
            sender = prefix.split("!")[0] if "!" in prefix else prefix

            # Only process messages from the channel (not DMs) and not from self
            if target.lower() == self.channel.lower() and sender != self.nick:
                self._handle_channel_message(sender, message)
            else:
                print(
                    f"[SlopLink IRC] Filtered message: target={target!r} "
                    f"channel={self.channel!r} sender={sender!r} nick={self.nick!r}",
                    file=sys.stderr,
                )

    def _handle_channel_message(self, sender: str, text: str) -> None:
        """Buffer and reassemble multi-line messages from a sender."""
        with self._reassembly_lock:
            now = time.time()
            if sender in self._reassembly:
                fragments, _ = self._reassembly[sender]
                fragments.append(text)
                self._reassembly[sender] = (fragments, now)
            else:
                self._reassembly[sender] = ([text], now)

    def _check_reassembly_timeout(self) -> None:
        """Deliver reassembled messages after timeout."""
        with self._reassembly_lock:
            now = time.time()
            to_deliver = []
            for sender, (fragments, last_time) in list(self._reassembly.items()):
                if now - last_time >= self.reassembly_timeout:
                    full_text = " ".join(fragments)
                    to_deliver.append(full_text)
                    print(
                        f"[SlopLink IRC] Delivering {len(fragments)} fragments "
                        f"({len(full_text)} chars) from {sender}",
                        file=sys.stderr,
                    )
                    del self._reassembly[sender]

        for text in to_deliver:
            if self._callback:
                self._callback(text)

    def send(self, text: str) -> None:
        """Send text to the IRC channel, splitting into chunks if needed."""
        # Collapse newlines for IRC (single-line protocol)
        flat = text.replace("\n", " ").replace("\r", "")

        # Split into IRC-safe chunks
        chunks = []
        while flat:
            if len(flat.encode("utf-8")) <= self.MAX_MSG_LEN:
                chunks.append(flat)
                break
            # Find a split point (prefer space boundary)
            split_at = self.MAX_MSG_LEN
            encoded = flat[:split_at].encode("utf-8")
            while len(encoded) > self.MAX_MSG_LEN and split_at > 100:
                split_at -= 1
                encoded = flat[:split_at].encode("utf-8")
            # Try to split at a space
            space_idx = flat.rfind(" ", 0, split_at)
            if space_idx > split_at // 2:
                split_at = space_idx + 1
            chunks.append(flat[:split_at])
            flat = flat[split_at:]

        for chunk in chunks:
            self._irc_send(f"PRIVMSG {self.channel} :{chunk}")
            time.sleep(0.3)  # Rate limit

    def disconnect(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._irc_send(f"PART {self.channel} :SlopLink signing off")
                self._irc_send("QUIT :Goodbye")
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None and self._running and self._joined.is_set()
