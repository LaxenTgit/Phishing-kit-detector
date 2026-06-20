"""
Central configuration for phishing-detector.
All tuneable constants live here — no magic numbers scattered across modules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass(frozen=True)
class ModuleWeights:
    """Weighted contribution of each analysis module to the final risk score."""
    html: float = 0.35
    dns: float = 0.30
    ssl: float = 0.20
    favicon: float = 0.15

    def as_dict(self) -> Dict[str, float]:
        return {
            "html": self.html,
            "dns": self.dns,
            "ssl": self.ssl,
            "favicon": self.favicon,
        }


@dataclass(frozen=True)
class RiskThresholds:
    """Score boundaries for each risk level (inclusive lower, exclusive upper)."""
    SAFE:     Tuple[float, float] = (0,   15)
    LOW:      Tuple[float, float] = (15,  35)
    MEDIUM:   Tuple[float, float] = (35,  55)
    HIGH:     Tuple[float, float] = (55,  75)
    CRITICAL: Tuple[float, float] = (75, 101)

    def level_for(self, score: float) -> str:
        for level in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            lo, hi = getattr(self, level)
            if lo <= score < hi:
                return level
        return "UNKNOWN"


@dataclass(frozen=True)
class HTTPConfig:
    timeout: int = 12
    max_redirects: int = 10
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    headers: Dict[str, str] = field(default_factory=lambda: {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })


# Brands that phishing kits commonly impersonate
BRAND_KEYWORDS: Tuple[str, ...] = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "instagram", "facebook", "twitter", "linkedin", "steam", "discord",
    "binance", "coinbase", "kraken", "bankofamerica", "chase", "wellsfargo",
    "dhl", "fedex", "ups", "irs", "gov", "ebay", "dropbox", "adobe",
    "office365", "outlook", "yahoo", "stripe", "shopify",
)

# Registrars frequently abused for phishing infrastructure
SUSPICIOUS_REGISTRARS: Tuple[str, ...] = (
    "namecheap", "reg.ru", "nicenic", "publicdomainregistry",
    "hostinger", "porkbun", "1api", "epik",
)

# Certificate Authorities commonly abused (free = easy = phishing)
FREE_CA_ISSUERS: Tuple[str, ...] = (
    "let's encrypt", "zerossl", "buypass", "google trust services",
)

# JS patterns indicating obfuscation / packing
JS_OBFUSCATION_PATTERNS: Tuple[str, ...] = (
    r"eval\(unescape\(",
    r"eval\(atob\(",
    r"String\.fromCharCode\(",
    r"\\x[0-9a-fA-F]{2}{4,}",
    r"\\u[0-9a-fA-F]{4}{4,}",
    r"document\.write\(unescape",
    r"window\[.{1,20}\]\[.{1,20}\]",
    r"_0x[a-f0-9]{4,}\(",
    r"parseInt\(.+,\s*0x",
)

# Suspicious PHP endpoint patterns in form actions
SUSPICIOUS_FORM_ENDPOINTS: Tuple[str, ...] = (
    r"gate\.php",
    r"log(in|ger)?\.php",
    r"(submit|send|post|process|action|panel|upload)\.php",
    r"grab\.php",
    r"checker\.php",
)

# Known favicon MD5 hashes of impersonated brands
# Populate with real values from brand sites
KNOWN_BRAND_FAVICON_HASHES: Dict[str, list] = {
    "paypal":    [],
    "google":    [],
    "microsoft": [],
    "amazon":    [],
    "apple":     [],
    "steam":     [],
    "discord":   [],
}

# Global singleton config instances
WEIGHTS    = ModuleWeights()
THRESHOLDS = RiskThresholds()
HTTP       = HTTPConfig()
