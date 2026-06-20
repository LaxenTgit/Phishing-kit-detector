#!/usr/bin/env python3
"""phishing-detector — Modular phishing page analysis toolkit."""

from __future__ import annotations

from .config import VERSION as __version__
from .core import PhishingDetector

__all__ = ["PhishingDetector", "__version__"]
