#!/usr/bin/env python3
"""
DEPRECATED: Use 'from slopcrypt.encode import ...' or 'python -m slopcrypt.encode' instead.

This module is a compatibility wrapper that re-exports from slopcrypt.encode.
It will be removed in a future version.
"""
import warnings

warnings.warn(
    "stego_basek.py is deprecated. Use 'from slopcrypt.encode import ...' "
    "or 'python -m slopcrypt.encode' instead.",
    DeprecationWarning,
    stacklevel=2,
)

from slopcrypt.encode import (
    DEFAULT_K,
    DEFAULT_PROMPT,
    decode,
    decode_with_knock,
    encode,
    encode_with_knock,
    main,
    sample_from_distribution,
)

__all__ = [
    "DEFAULT_K",
    "DEFAULT_PROMPT",
    "encode",
    "encode_with_knock",
    "decode",
    "decode_with_knock",
    "sample_from_distribution",
    "main",
]

if __name__ == "__main__":
    main()
