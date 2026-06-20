"""
Favicon analysis module.
Downloads the favicon, hashes it (MD5 + MMH3 for Shodan compatibility),
and checks for brand impersonation via known hash lists.
"""

from __future__ import annotations

import hashlib
import struct
import re
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from phishing_detector.config import HTTP, KNOWN_BRAND_FAVICON_HASHES
from phishing_detector.models import FaviconResult
from phishing_detector.utils import extract_domain, get_logger

logger = get_logger(__name__)

_HEADERS = {"User-Agent": HTTP.user_agent}


def analyze(html: str, url: str) -> FaviconResult:
    result  = FaviconResult()
    favicon_url = _find_favicon_url(html, url)

    if not favicon_url:
        result.add_error("Could not determine favicon URL")
        return result

    result.favicon_url = favicon_url

    # Flag favicon hosted on a different domain
    page_domain    = extract_domain(url)
    favicon_domain = extract_domain(favicon_url)
    if favicon_domain and favicon_domain != page_domain:
        result.external_host = True
        result.add_flag(f"Favicon served from external domain: '{favicon_domain}'", 15)
        # Extra penalty if external host is a known brand
        for brand in KNOWN_BRAND_FAVICON_HASHES:
            if brand in favicon_domain:
                result.add_flag(
                    f"Favicon hotlinked directly from '{brand}' brand domain", 20
                )
                break

    _download_and_hash(favicon_url, result)
    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _find_favicon_url(html: str, base_url: str) -> str | None:
    soup      = BeautifulSoup(html, "html.parser")
    base_root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

    # Ordered preference: shortcut icon → apple-touch → first icon → /favicon.ico
    selectors = [
        {"rel": re.compile(r"shortcut icon", re.I)},
        {"rel": re.compile(r"apple-touch-icon", re.I)},
        {"rel": re.compile(r"icon", re.I)},
    ]
    for attrs in selectors:
        tag = soup.find("link", attrs=attrs)
        if tag and tag.get("href"):
            href = tag["href"].strip()
            return href if href.startswith("http") else urljoin(base_root, href)

    return urljoin(base_root, "/favicon.ico")


def _mmh3_hash(data: bytes) -> int:
    """
    MurmurHash3 32-bit (x86) — used by Shodan for favicon indexing.
    Pure-Python implementation to avoid a C extension dependency.
    """
    length = len(data)
    nblocks = length // 4
    h1 = 0
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail_index = nblocks * 4
    tail = data[tail_index:]
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    # fmix32
    h1 ^= h1 >> 16
    h1  = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1  = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit (Shodan uses signed)
    return h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1


def _download_and_hash(favicon_url: str, result: FaviconResult) -> None:
    try:
        r = requests.get(favicon_url, headers=_HEADERS, timeout=6, stream=True)
        if r.status_code != 200:
            result.add_error(f"Favicon returned HTTP {r.status_code}")
            return

        data = r.content
        md5_hash  = hashlib.md5(data).hexdigest()
        mmh3_hash = _mmh3_hash(data)

        result.favicon_hash = md5_hash
        logger.debug("Favicon MD5: %s  MMH3: %d", md5_hash, mmh3_hash)

        # Match against known brand hashes
        for brand, hashes in KNOWN_BRAND_FAVICON_HASHES.items():
            if md5_hash in hashes:
                result.matched_brand = brand
                result.add_flag(
                    f"Favicon hash matches known brand '{brand}' — strong impersonation indicator",
                    35,
                )
                return

    except requests.exceptions.Timeout:
        result.add_error("Favicon request timed out")
    except Exception as exc:  # noqa: BLE001
        result.add_error(f"Favicon download error: {exc}")
        logger.debug("Favicon error: %s", exc, exc_info=True)
