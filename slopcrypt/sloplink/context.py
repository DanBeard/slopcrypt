"""
Conversation context manager for SlopLink.

Tracks the rolling chat history so both peers can reconstruct the same
LLM prompt for encoding/decoding. The prompt is derived from the last N
messages in the conversation.
"""

from __future__ import annotations


class ConversationContext:
    """
    Maintains a shared conversation history between SlopLink peers.

    Both peers see the same messages (they're on the same chat channel),
    so they can independently reconstruct the same prompt for encoding
    and decoding. The prompt for the next message is always derived from
    the last `window_size` messages.
    """

    def __init__(self, window_size: int = 1, seed_prompt: str = ""):
        """
        Args:
            window_size: Number of recent messages to use as prompt context.
            seed_prompt: Default prompt when conversation history is empty.
        """
        self.window_size = window_size
        self.messages: list[str] = []
        self.seed_prompt = seed_prompt

    def add_message(self, text: str) -> None:
        """Add a message to the conversation history."""
        self.messages.append(text)

    def get_prompt(self) -> str:
        """
        Build the LLM prompt from recent conversation history.

        Both peers call this BEFORE a message is added to get the prompt
        that was (or will be) used for encoding. This ensures encoder and
        decoder use the same prompt.

        Returns:
            The prompt string derived from the last N messages.
        """
        if not self.messages:
            return self.seed_prompt

        recent = self.messages[-self.window_size :]
        return "\n\n".join(recent)

    def clear(self) -> None:
        """Reset the conversation history."""
        self.messages.clear()

    def __len__(self) -> int:
        return len(self.messages)
