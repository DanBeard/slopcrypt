"""
DEPRECATED: Use 'from slopcrypt.utils import ...' instead.

This module is a compatibility wrapper that re-exports from slopcrypt.utils.
It will be removed in a future version.
"""
import warnings

warnings.warn(
    "utils.py is deprecated. Use 'from slopcrypt.utils import ...' instead.",
    DeprecationWarning,
    stacklevel=2,
)

from slopcrypt.utils import (
    TokenProb,
    bits_to_bytes,
    bits_to_int,
    bytes_to_bits,
    check_knock_in_data,
    filter_prefix_tokens,
    find_knock_sequence,
    find_longest_match,
    int_to_bits,
    parse_knock_sequence,
)

__all__ = [
    "TokenProb",
    "bytes_to_bits",
    "bits_to_bytes",
    "bits_to_int",
    "int_to_bits",
    "filter_prefix_tokens",
    "find_longest_match",
    "parse_knock_sequence",
    "find_knock_sequence",
    "check_knock_in_data",
]
