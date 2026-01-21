"""
DEPRECATED: Use 'from slopcrypt.lm_client import ...' instead.

This module is a compatibility wrapper that re-exports from slopcrypt.lm_client.
It will be removed in a future version.
"""
import warnings

warnings.warn(
    "lm_client.py is deprecated. Use 'from slopcrypt.lm_client import ...' instead.",
    DeprecationWarning,
    stacklevel=2,
)

from slopcrypt.lm_client import (
    DEFAULT_HOST,
    DEFAULT_MODEL,
    DEFAULT_MODEL_PATH,
    FixedDistributionClient,
    LlamaCppClient,
    LMClient,
    LMConfig,
    MLXClient,
    MockLMClient,
)
from slopcrypt.utils import TokenProb

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_MODEL",
    "DEFAULT_MODEL_PATH",
    "LlamaCppClient",
    "LMConfig",
    "LMClient",
    "MLXClient",
    "MockLMClient",
    "FixedDistributionClient",
    "TokenProb",
]
