"""
DNS & WHOIS analysis module.
Checks domain age, registrar abuse patterns, subdomain brand abuse,
basic typosquatting, and raw-IP URL detection.
"""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import whois

from phishing_detector.config import BRAND_KEYWORDS, SUSPICIOUS_REGISTRARS
from phishing_detector.models import DNSResult
from phishing_detector.utils import extract_domain, extract_root_domain, is_ip_address, get_logger

logger = get_logger(__name__)

# Simple homoglyph / typosquatting substitution map
_TYPO_SUBS: dict[str, str] = {
    "paypa1": "paypal",
    "paypai": "paypal",
    "paypa|": "paypal",
    "micros0ft": "microsoft",
    "g00gle": "google",
    "arnazon": "amazon",
    "facebok": "facebook",
    "lnstagram": "instagram",
    "linkedln": "linkedin",
    "stearn": "steam",
    "discorcl": "discord",
    "b1nance": "binance",
}


def analyze(url: str) -> DNSResult:
    result = DNSResult()
    domain = extract_domain(url)
    result.domain = domain

    # Raw IP in URL
    if is_ip_address(domain):
        result.add_flag(f"URL uses raw IP address '{domain}' instead of a domain name", 25)
        result.ip = domain
        return result

    _check_whois(domain, result)
    _check_dns(domain, result)
    _check_subdomain_abuse(domain, result)
    _check_typosquatting(domain, result)

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _parse_date(raw) -> Optional[datetime]:
    """Normalise WHOIS date fields (may be list, naive, or already tz-aware)."""
    if isinstance(raw, list):
        raw = raw[0]
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw
    # Try common string formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            return datetime.strptime(str(raw), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _check_whois(domain: str, result: DNSResult) -> None:
    try:
        w = whois.whois(domain)

        # Domain age
        creation = _parse_date(w.creation_date)
        if creation:
            age_days = (datetime.now(timezone.utc) - creation).days
            result.age_days      = age_days
            result.creation_date = creation.isoformat()

            if age_days < 7:
                result.add_flag(f"Domain is only {age_days} day(s) old — extremely new", 30)
            elif age_days < 30:
                result.add_flag(f"Domain is {age_days} days old — very recently registered", 20)
            elif age_days < 90:
                result.add_flag(f"Domain is {age_days} days old — still relatively new", 10)

        # Registrar
        registrar = (w.registrar or "").strip()
        result.registrar = registrar or None
        if any(r in registrar.lower() for r in SUSPICIOUS_REGISTRARS):
            result.add_flag(f"Registered via commonly-abused registrar: '{registrar}'", 8)

        # WHOIS privacy shield
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        protected = (
            not emails
            or any(kw in " ".join(emails).lower() for kw in ("privacy", "protect", "redacted", "proxy"))
        )
        result.whois_protected = protected
        if protected:
            result.add_flag("WHOIS registrant identity hidden behind privacy service", 5)

    except Exception as exc:
        result.add_error(f"WHOIS lookup failed: {exc}")
        logger.debug("WHOIS error for %s: %s", domain, exc)


def _check_dns(domain: str, result: DNSResult) -> None:
    try:
        ip = socket.gethostbyname(domain)
        result.ip = ip
    except socket.gaierror as exc:
        result.add_flag("DNS resolution failed — domain may be suspended or non-existent", 15)
        result.add_error(f"DNS error: {exc}")


def _check_subdomain_abuse(domain: str, result: DNSResult) -> None:
    """Flag domains where a brand name appears in the subdomain portion."""
    root = extract_root_domain(domain)
    subdomain_part = domain[: len(domain) - len(root) - 1].lower()  # everything left of root

    if not subdomain_part:
        return

    for brand in BRAND_KEYWORDS:
        if brand in subdomain_part:
            result.add_flag(
                f"Brand '{brand}' used in subdomain — classic phishing domain pattern: '{domain}'",
                25,
            )
            return


def _check_typosquatting(domain: str, result: DNSResult) -> None:
    d = domain.lower()
    for typo, real_brand in _TYPO_SUBS.items():
        if typo in d:
            result.add_flag(
                f"Domain '{domain}' appears to typosquat '{real_brand}' (matched: '{typo}')",
                25,
            )
            return

    # Check for brand + extra TLD (e.g. paypal.com.evil.net)
    root = extract_root_domain(domain)
    leftover = domain[: len(domain) - len(root) - 1]
    for brand in BRAND_KEYWORDS:
        if f"{brand}.com" in leftover or f"{brand}.net" in leftover:
            result.add_flag(
                f"Legitimate domain used as subdomain in '{domain}' — URL deception technique",
                30,
            )
            return
