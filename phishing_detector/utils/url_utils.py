#!/usr/bin/env python3
"""URL normalisation and domain extraction utilities."""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse


def normalise_url(raw: str) -> str:
    """Ensure URL has a scheme."""
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    return raw


def extract_domain(url: str) -> str:
    """Extract hostname without port."""
    return urlparse(url).netloc.split(":")[0]


def extract_root_domain(url: str) -> str:
    """Extract the root domain (last two labels)."""
    parts = extract_domain(url).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else extract_domain(url)


def is_ip(host: str) -> bool:
    """Check if host is an IP address (IPv4 or IPv6)."""
    host = host.split(":")[0]
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            pass
    return False
