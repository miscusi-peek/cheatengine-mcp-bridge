"""Feature discovery helpers for building new CT features from nearby references."""

from .discovery import build_feature_packet
from .reference_lookup import find_reference_entry

__all__ = ["build_feature_packet", "find_reference_entry"]
