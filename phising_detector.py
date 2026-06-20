#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════╗
║           phishing-detector  cats                 ║
║           github.com/LaxenTgit                    ║
╚═══════════════════════════════════════════════════╝

Modular phishing page analysis toolkit — single-file edition.
Combines HTML/JS analysis, DNS/WHOIS, SSL, and favicon fingerprinting
into a weighted 0-100 risk score.

Usage:
    python phishing_detector.py <url> [-v] [-o json] [-f out.json]
    python phishing_detector.py --batch urls.txt -v
"""

from __future__ import annotations

# ── stdlib ──────────────────────────────────────────────────────────────────
import argparse
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

# ── third-party ─────────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from bs4 import BeautifulSoup
    import whois
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    pip install requests beautifulsoup4 python-whois")
    sys.exit(1)

# ════════════════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

BRAND_KEYWORDS: Tuple[str, ...] = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "instagram", "facebook", "twitter", "linkedin", "steam", "discord",
    "binance", "coinbase", "kraken", "bankofamerica", "chase", "wellsfargo",
    "dhl", "fedex", "ups", "irs", "gov", "ebay", "dropbox", "adobe",
    "office365", "outlook", "yahoo", "stripe", "shopify",
)

SUSPICIOUS_REGISTRARS: Tuple[str, ...] = (
    "namecheap", "reg.ru", "nicenic", "publicdomainregistry",
    "hostinger", "porkbun", "1api", "epik",
)

FREE_CA_ISSUERS: Tuple[str, ...] = (
    "let's encrypt", "zerossl", "buypass", "google trust services",
)

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

SUSPICIOUS_FORM_ENDPOINTS: Tuple[str, ...] = (
    r"gate\.php",
    r"log(in|ger)?\.php",
    r"(submit|send|post|process|action|panel|upload)\.php",
    r"grab\.php",
    r"checker\.php",
)

_TYPO_SUBS: Dict[str, str] = {
    "paypa1": "paypal", "paypai": "paypal", "paypa|": "paypal",
    "micros0ft": "microsoft", "g00gle": "google", "arnazon": "amazon",
    "facebok": "facebook", "lnstagram": "instagram", "linkedln": "linkedin",
    "stearn": "steam", "discorcl": "discord", "b1nance": "binance",
}

# Favicon MD5 hashes — populate with real values from brand sites
KNOWN_BRAND_FAVICON_HASHES: Dict[str, list] = {
    "paypal": [], "google": [], "microsoft": [],
    "amazon": [], "apple": [],  "steam": [], "discord": [],
}

MODULE_WEIGHTS = {"html": 0.35, "dns": 0.30, "ssl": 0.20, "favicon": 0.15}

RISK_THRESHOLDS = [
    (0,   15,  "SAFE"),
    (15,  35,  "LOW"),
    (35,  55,  "MEDIUM"),
    (55,  75,  "HIGH"),
    (75,  101, "CRITICAL"),
]

HTTP_TIMEOUT    = 12
HTTP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "DNT": "1",
}

# ════════════════════════════════════════════════════════════════════════════
# TERMINAL COLOURS
# ════════════════════════════════════════════════════════════════════════════

_NO_COLOR = bool(os.getenv("NO_COLOR"))

def _c(code: str) -> str:
    return "" if _NO_COLOR else code

RESET    = _c("\033[0m")
BOLD     = _c("\033[1m")
DIM      = _c("\033[2m")
CYAN     = _c("\033[96m")
YELLOW   = _c("\033[93m")
RED      = _c("\033[91m")
GREEN    = _c("\033[92m")
RED_BOLD = _c("\033[91m\033[1m")

LEVEL_COLORS = {
    "SAFE":     GREEN,
    "LOW":      YELLOW,
    "MEDIUM":   YELLOW,
    "HIGH":     RED,
    "CRITICAL": RED_BOLD,
}

def step(msg: str)    -> None: print(f"{CYAN}[*]{RESET} {msg}")
def ok(msg: str)      -> None: print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg: str)    -> None: print(f"{YELLOW}[!]{RESET} {msg}")
def err(msg: str)     -> None: print(f"{RED}[✗]{RESET} {msg}", file=sys.stderr)

# ════════════════════════════════════════════════════════════════════════════
# MODELS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class ModuleResult:
    flags:  List[str] = field(default_factory=list)
    score:  int       = 0
    errors: List[str] = field(default_factory=list)

    def flag(self, msg: str, pts: int) -> None:
        self.flags.append(msg)
        self.score = min(self.score + pts, 100)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def to_dict(self) -> Dict[str, Any]:
        return {"flags": self.flags, "score": self.score, "errors": self.errors}


@dataclass
class FetchResult(ModuleResult):
    success:         bool            = False
    status_code:     Optional[int]   = None
    html:            str             = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    final_url:       str             = ""
    redirect_chain:  List[str]       = field(default_factory=list)
    content_type:    str             = ""

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"success": self.success, "status_code": self.status_code,
                  "final_url": self.final_url, "redirect_chain": self.redirect_chain})
        return d


@dataclass
class HTMLResult(ModuleResult):
    title: str = ""; form_count: int = 0
    script_count: int = 0; iframe_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"title": self.title, "form_count": self.form_count,
                  "script_count": self.script_count, "iframe_count": self.iframe_count})
        return d


@dataclass
class DNSResult(ModuleResult):
    domain: str = ""; ip: Optional[str] = None
    age_days: Optional[int] = None; creation_date: Optional[str] = None
    registrar: Optional[str] = None; whois_protected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"domain": self.domain, "ip": self.ip, "age_days": self.age_days,
                  "registrar": self.registrar, "whois_protected": self.whois_protected})
        return d


@dataclass
class SSLResult(ModuleResult):
    scheme: str = ""; issuer_org: Optional[str] = None
    cert_age_days: Optional[int] = None; cert_valid_days: Optional[int] = None
    issued: Optional[str] = None; expires: Optional[str] = None
    san: List[str] = field(default_factory=list); wildcard: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"scheme": self.scheme, "issuer_org": self.issuer_org,
                  "cert_age_days": self.cert_age_days, "san": self.san})
        return d


@dataclass
class FaviconResult(ModuleResult):
    favicon_url: Optional[str] = None; favicon_hash: Optional[str] = None
    matched_brand: Optional[str] = None; external_host: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"favicon_url": self.favicon_url, "favicon_hash": self.favicon_hash,
                  "matched_brand": self.matched_brand})
        return d


@dataclass
class ScoreBreakdown:
    module: str = ""; raw_score: int = 0
    weight: float = 0.0; contribution: float = 0.0


@dataclass
class AnalysisResult:
    url: str = ""; final_url: str = ""; timestamp: str = ""
    total_score: float = 0.0; level: str = "UNKNOWN"
    all_flags: List[str] = field(default_factory=list)
    breakdown: List[ScoreBreakdown] = field(default_factory=list)
    fetch:   Optional[FetchResult]   = None
    html:    Optional[HTMLResult]    = None
    dns:     Optional[DNSResult]     = None
    ssl:     Optional[SSLResult]     = None
    favicon: Optional[FaviconResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "final_url": self.final_url,
            "timestamp": self.timestamp, "total_score": self.total_score,
            "level": self.level, "all_flags": self.all_flags,
            "breakdown": [
                {"module": b.module, "raw_score": b.raw_score,
                 "weight": b.weight, "contribution": b.contribution}
                for b in self.breakdown
            ],
            "modules": {
                "fetch":   self.fetch.to_dict()   if self.fetch   else {},
                "html":    self.html.to_dict()    if self.html    else {},
                "dns":     self.dns.to_dict()     if self.dns     else {},
                "ssl":     self.ssl.to_dict()     if self.ssl     else {},
                "favicon": self.favicon.to_dict() if self.favicon else {},
            },
        }

# ════════════════════════════════════════════════════════════════════════════
# URL UTILS
# ════════════════════════════════════════════════════════════════════════════

def normalise_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    return raw

def extract_domain(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]

def extract_root_domain(url: str) -> str:
    parts = extract_domain(url).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else extract_domain(url)

def is_ip(host: str) -> bool:
    host = host.split(":")[0]
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            pass
    return False

# ════════════════════════════════════════════════════════════════════════════
# MODULE 1 — FETCHER
# ════════════════════════════════════════════════════════════════════════════

def fetch(url: str, timeout: int = HTTP_TIMEOUT) -> FetchResult:
    result  = FetchResult()
    session = requests.Session()
    session.headers.update({"User-Agent": HTTP_USER_AGENT, **HTTP_HEADERS})
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET"])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://",  HTTPAdapter(max_retries=retry))

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        result.success         = True
        result.status_code     = r.status_code
        result.html            = r.text
        result.response_headers = dict(r.headers)
        result.final_url       = r.url
        result.content_type    = r.headers.get("Content-Type", "")
        result.redirect_chain  = [x.url for x in r.history]

        orig_domain  = extract_domain(url)
        final_domain = extract_domain(r.url)
        if orig_domain != final_domain:
            result.flag(f"Domain changed after redirect: {orig_domain} → {final_domain}", 10)
        if len(result.redirect_chain) > 3:
            result.flag(f"Excessive redirect chain ({len(result.redirect_chain)} hops)", 10)
        if r.status_code >= 400:
            result.flag(f"HTTP {r.status_code} response", 5)

        headers_lc = {k.lower() for k in r.headers}
        missing = {"x-frame-options", "content-security-policy", "x-content-type-options"} - headers_lc
        if len(missing) == 3:
            result.flag("All major security headers absent", 5)

    except requests.exceptions.SSLError as e:
        result.flag("SSL handshake failed — invalid or self-signed certificate", 25)
        result.error(str(e))
    except requests.exceptions.TooManyRedirects:
        result.flag("Redirect loop detected", 15)
        result.error("Too many redirects")
    except requests.exceptions.ConnectionError as e:
        result.error(f"Connection error: {e}")
    except requests.exceptions.Timeout:
        result.error("Request timed out")
    except Exception as e:
        result.error(f"Unexpected error: {e}")

    return result

# ════════════════════════════════════════════════════════════════════════════
# MODULE 2 — HTML ANALYZER
# ════════════════════════════════════════════════════════════════════════════

def analyze_html(html: str, original_url: str, final_url: str) -> HTMLResult:
    result = HTMLResult()
    soup   = BeautifulSoup(html, "html.parser")
    domain = extract_domain(final_url)

    # Title brand mismatch
    title_tag = soup.find("title")
    title     = title_tag.get_text(strip=True) if title_tag else ""
    result.title = title
    for brand in BRAND_KEYWORDS:
        if brand in title.lower() and brand not in domain:
            result.flag(f"Page title claims '{brand}' but domain is '{domain}'", 20)
            break

    # Forms
    forms = soup.find_all("form")
    for form in forms:
        action = (form.get("action") or "").strip()
        if action:
            action_domain = urlparse(action).netloc
            if action_domain and action_domain != domain:
                result.flag(f"Form submits to external domain: {action_domain}", 25)
            for pat in SUSPICIOUS_FORM_ENDPOINTS:
                if re.search(pat, action, re.I):
                    result.flag(f"Suspicious form endpoint: '{action}'", 15)
                    break
        else:
            if form.find("input", {"type": "password"}):
                result.flag("Password form with empty action — JS credential theft likely", 20)

        has_pw   = bool(form.find("input", {"type": "password"}))
        has_user = bool(form.find("input", attrs={"name": re.compile(r"user|email|login|account", re.I)}))
        if has_pw and has_user:
            result.flag("Credential harvest form detected (username + password)", 10)
            break

    # Hotlinked brand resources
    seen: set[str] = set()
    for tag in soup.find_all(["img", "link", "script"]):
        src = (tag.get("src") or tag.get("href") or "").strip()
        src_domain = urlparse(src).netloc
        if not src_domain or src_domain == domain or src_domain in seen:
            continue
        for brand in BRAND_KEYWORDS:
            if brand in src_domain:
                result.flag(f"Resource hotlinked from brand domain '{src_domain}'", 15)
                seen.add(src_domain)
                break

    # JS obfuscation
    scripts  = soup.find_all("script")
    combined = " ".join(s.get_text() for s in scripts if s.get_text())
    hits = 0
    for pat in JS_OBFUSCATION_PATTERNS:
        if hits >= 3:
            break
        if re.search(pat, combined):
            result.flag(f"JS obfuscation pattern: {pat}", 10)
            hits += 1

    # Kit artifacts
    if re.search(r'["\'].*?\.zip["\']', html, re.I):
        result.flag("ZIP file reference in HTML source — possible kit artifact", 10)
    if re.search(r'(include|require).*?mailer\.php', html, re.I):
        result.flag("PHP mailer include found — common in phishing kits", 15)

    # Hidden iframes
    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").replace(" ", "").lower()
        if ("display:none" in style or "visibility:hidden" in style
                or iframe.has_attr("hidden") or iframe.get("width") == "0"):
            result.flag(f"Hidden iframe detected (src: {iframe.get('src','N/A')})", 10)

    # Meta refresh
    meta = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
    if meta:
        result.flag(f"Meta-refresh redirect: '{meta.get('content','')}'", 10)

    # Copyright mismatch
    text = soup.get_text(separator=" ").lower()
    for brand in BRAND_KEYWORDS:
        if any(p in text for p in [f"© {brand}", f"copyright {brand}", f"{brand}, inc"]):
            if brand not in domain:
                result.flag(f"Page claims '{brand}' copyright but domain is '{domain}'", 15)
                break

    result.form_count   = len(forms)
    result.script_count = len(scripts)
    result.iframe_count = len(soup.find_all("iframe"))
    return result

# ════════════════════════════════════════════════════════════════════════════
# MODULE 3 — DNS / WHOIS
# ════════════════════════════════════════════════════════════════════════════

def _parse_whois_date(raw) -> Optional[datetime]:
    if isinstance(raw, list):
        raw = raw[0]
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=timezone.utc) if raw.tzinfo is None else raw
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            return datetime.strptime(str(raw), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def analyze_dns(url: str) -> DNSResult:
    result = DNSResult()
    domain = extract_domain(url)
    result.domain = domain

    if is_ip(domain):
        result.flag(f"URL uses raw IP '{domain}' instead of a domain", 25)
        result.ip = domain
        return result

    # WHOIS
    try:
        w          = whois.whois(domain)
        creation   = _parse_whois_date(w.creation_date)
        if creation:
            age = (datetime.now(timezone.utc) - creation).days
            result.age_days      = age
            result.creation_date = creation.isoformat()
            if age < 7:
                result.flag(f"Domain is only {age} day(s) old — extremely new", 30)
            elif age < 30:
                result.flag(f"Domain is {age} days old — very recently registered", 20)
            elif age < 90:
                result.flag(f"Domain is {age} days old — still relatively new", 10)

        registrar = (w.registrar or "").strip()
        result.registrar = registrar or None
        if any(r in registrar.lower() for r in SUSPICIOUS_REGISTRARS):
            result.flag(f"Commonly-abused registrar: '{registrar}'", 8)

        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        if not emails or any(k in " ".join(emails).lower() for k in ("privacy","protect","redacted","proxy")):
            result.whois_protected = True
            result.flag("WHOIS registrant identity hidden", 5)

    except Exception as e:
        result.error(f"WHOIS failed: {e}")

    # DNS
    try:
        result.ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        result.flag("DNS resolution failed — domain may not exist", 15)
        result.error(str(e))

    # Subdomain brand abuse
    root      = extract_root_domain(url)
    subdomain = domain[: len(domain) - len(root) - 1].lower()
    if subdomain:
        for brand in BRAND_KEYWORDS:
            if brand in subdomain:
                result.flag(f"Brand '{brand}' injected into subdomain: '{domain}'", 25)
                break

    # Typosquatting
    d = domain.lower()
    for typo, real in _TYPO_SUBS.items():
        if typo in d:
            result.flag(f"Possible typosquat of '{real}': '{domain}'", 25)
            break

    # Legit domain used as subdomain (e.g. paypal.com.evil.ru)
    leftover = domain[: len(domain) - len(root) - 1]
    for brand in BRAND_KEYWORDS:
        if f"{brand}.com" in leftover or f"{brand}.net" in leftover:
            result.flag(f"Legit domain embedded as subdomain in '{domain}' — URL deception", 30)
            break

    return result

# ════════════════════════════════════════════════════════════════════════════
# MODULE 4 — SSL
# ════════════════════════════════════════════════════════════════════════════

def analyze_ssl(url: str) -> SSLResult:
    result = SSLResult()
    parsed = urlparse(url)
    result.scheme = parsed.scheme

    if parsed.scheme == "http":
        result.flag("Site served over plain HTTP — no encryption", 20)
        return result

    hostname = extract_domain(url)
    port     = int(parsed.port or 443)

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((hostname, port), timeout=8),
                               server_hostname=hostname)
        cert = conn.getpeercert()
        conn.close()

        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert["notAfter"],  fmt).replace(tzinfo=timezone.utc)
        now        = datetime.now(timezone.utc)

        age_days   = (now - not_before).days
        valid_days = (not_after - not_before).days

        result.issued          = not_before.isoformat()
        result.expires         = not_after.isoformat()
        result.cert_age_days   = age_days
        result.cert_valid_days = valid_days

        if age_days < 3:
            result.flag(f"Certificate issued {age_days} day(s) ago — extremely fresh", 20)
        elif age_days < 14:
            result.flag(f"Certificate issued {age_days} days ago — very recently issued", 12)
        elif age_days < 30:
            result.flag(f"Certificate is only {age_days} days old", 6)

        if valid_days <= 90:
            result.flag(f"Short-lived cert ({valid_days}-day validity) — common in phishing infra", 10)

        issuer = {k: v for item in cert.get("issuer", []) for k, v in item}
        org    = issuer.get("organizationName", "")
        result.issuer_org = org or None
        if any(ca in org.lower() for ca in FREE_CA_ISSUERS):
            result.flag(f"Free CA '{org}' — widely abused for phishing", 8)

        san_list      = [v for _, v in cert.get("subjectAltName", [])]
        result.san    = san_list
        result.wildcard = any("*" in s for s in san_list)

        if result.wildcard:
            result.flag("Wildcard certificate — covers all subdomains", 5)
        elif san_list and hostname not in san_list:
            result.flag(f"Hostname '{hostname}' not in certificate SAN list", 20)

    except ssl.SSLCertVerificationError as e:
        result.flag(f"SSL certificate verification failed: {e}", 30)
    except ssl.SSLError as e:
        result.flag(f"SSL error: {e}", 20)
    except ConnectionRefusedError:
        result.flag("Connection refused on port 443", 5)
    except socket.timeout:
        result.flag("SSL handshake timed out", 5)
    except Exception as e:
        result.error(f"SSL check failed: {e}")

    return result

# ════════════════════════════════════════════════════════════════════════════
# MODULE 5 — FAVICON
# ════════════════════════════════════════════════════════════════════════════

def _mmh3(data: bytes) -> int:
    """MurmurHash3 32-bit — Shodan-compatible favicon hash."""
    length = len(data)
    nblocks = length // 4
    h1 = 0
    c1, c2 = 0xCC9E2D51, 0x1B873593
    for i in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = ((k1 * c1) & 0xFFFFFFFF)
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = ((k1 * c2) & 0xFFFFFFFF)
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    n  = length & 3
    if n >= 3: k1 ^= tail[2] << 16
    if n >= 2: k1 ^= tail[1] << 8
    if n >= 1:
        k1 ^= tail[0]
        k1  = ((k1 * c1) & 0xFFFFFFFF)
        k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1  = ((k1 * c2) & 0xFFFFFFFF)
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16; h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13; h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1


def analyze_favicon(html: str, url: str) -> FaviconResult:
    result    = FaviconResult()
    soup      = BeautifulSoup(html, "html.parser")
    base_root = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    page_domain = extract_domain(url)

    # Find favicon URL
    favicon_url = None
    for attrs in [{"rel": re.compile(r"shortcut icon", re.I)},
                  {"rel": re.compile(r"apple-touch-icon", re.I)},
                  {"rel": re.compile(r"icon", re.I)}]:
        tag = soup.find("link", attrs=attrs)
        if tag and tag.get("href"):
            href = tag["href"].strip()
            favicon_url = href if href.startswith("http") else urljoin(base_root, href)
            break
    if not favicon_url:
        favicon_url = urljoin(base_root, "/favicon.ico")

    result.favicon_url = favicon_url

    fav_domain = extract_domain(favicon_url)
    if fav_domain and fav_domain != page_domain:
        result.external_host = True
        result.flag(f"Favicon from external domain: '{fav_domain}'", 15)
        for brand in KNOWN_BRAND_FAVICON_HASHES:
            if brand in fav_domain:
                result.flag(f"Favicon hotlinked from '{brand}' brand domain", 20)
                break

    try:
        r = requests.get(favicon_url, headers={"User-Agent": HTTP_USER_AGENT}, timeout=6)
        if r.status_code == 200:
            data = r.content
            md5  = hashlib.md5(data).hexdigest()
            result.favicon_hash = md5
            for brand, hashes in KNOWN_BRAND_FAVICON_HASHES.items():
                if md5 in hashes:
                    result.matched_brand = brand
                    result.flag(f"Favicon hash matches '{brand}' — strong impersonation indicator", 35)
                    break
        else:
            result.error(f"Favicon returned HTTP {r.status_code}")
    except Exception as e:
        result.error(f"Favicon error: {e}")

    return result

# ════════════════════════════════════════════════════════════════════════════
# SCORER
# ════════════════════════════════════════════════════════════════════════════

def calculate_score(result: AnalysisResult) -> None:
    total     = 0.0
    all_flags = []
    breakdown = []

    for name, weight in MODULE_WEIGHTS.items():
        mod = getattr(result, name)
        raw = mod.score if mod else 0
        contrib = round(raw * weight, 2)
        total  += contrib
        breakdown.append(ScoreBreakdown(module=name, raw_score=raw,
                                        weight=weight, contribution=contrib))
        if mod:
            all_flags.extend(mod.flags)

    result.total_score = round(total, 1)
    result.all_flags   = all_flags
    result.breakdown   = breakdown

    for lo, hi, level in RISK_THRESHOLDS:
        if lo <= result.total_score < hi:
            result.level = level
            return
    result.level = "UNKNOWN"

# ════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════

def analyze(url: str, verbose: bool = False, timeout: int = HTTP_TIMEOUT) -> AnalysisResult:
    url    = normalise_url(url)
    result = AnalysisResult(url=url, timestamp=datetime.now(timezone.utc).isoformat())

    print(f"\n{'─'*54}")
    print(f"  phishing-detector v{VERSION}  |  {DIM}{url}{RESET}")
    print(f"{'─'*54}")

    step("Fetching page...")
    fetch_result = fetch(url, timeout)
    result.fetch = fetch_result

    if not fetch_result.success:
        for e in fetch_result.errors:
            err(e)
        warn("Fetch failed — running DNS/SSL checks only.")

    result.final_url = fetch_result.final_url or url

    step("Analysing HTML & JavaScript...")
    if fetch_result.html:
        result.html = analyze_html(fetch_result.html, url, result.final_url)
    else:
        result.html = HTMLResult()
        result.html.error("No HTML content")
    if verbose:
        for f in result.html.flags:
            print(f"    {DIM}[HTML]{RESET} {f}")

    step("Checking domain registration...")
    result.dns = analyze_dns(url)
    if verbose:
        for f in result.dns.flags:
            print(f"    {DIM}[DNS]{RESET} {f}")

    step("Inspecting SSL certificate...")
    result.ssl = analyze_ssl(result.final_url or url)
    if verbose:
        for f in result.ssl.flags:
            print(f"    {DIM}[SSL]{RESET} {f}")

    step("Fingerprinting favicon...")
    result.favicon = analyze_favicon(fetch_result.html or "", url)
    if verbose:
        for f in result.favicon.flags:
            print(f"    {DIM}[FAV]{RESET} {f}")

    calculate_score(result)
    return result

# ════════════════════════════════════════════════════════════════════════════
# REPORT RENDERER
# ════════════════════════════════════════════════════════════════════════════

def render_report(result: AnalysisResult) -> None:
    colour = LEVEL_COLORS.get(result.level, "")
    W = 54

    print(f"\n{'═'*W}")
    print(f"  RISK REPORT")
    print(f"{'─'*W}")
    print(f"  URL      {DIM}{result.url}{RESET}")
    print(f"  Score    {BOLD}{result.total_score}/100{RESET}")
    print(f"  Level    {colour}{BOLD}{result.level}{RESET}")
    print(f"{'─'*W}")
    print(f"  {'Module':<10}  {'Raw':>5}  {'Weight':>7}  {'Contrib':>8}")
    print(f"  {'─'*10}  {'─'*5}  {'─'*7}  {'─'*8}")
    for b in result.breakdown:
        print(f"  {b.module:<10}  {b.raw_score:>5}  {b.weight:>7.0%}  {b.contribution:>8.1f}")
    print(f"{'─'*W}")
    print(f"  Flags ({len(result.all_flags)}):")
    if result.all_flags:
        for f in result.all_flags:
            print(f"    {DIM}•{RESET} {f}")
    else:
        print(f"    {DIM}No significant indicators found.{RESET}")
    print(f"{'═'*W}\n")

# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing_detector",
        description="Modular phishing page analysis toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python phishing_detector.py https://suspicious.example.com
  python phishing_detector.py https://suspicious.example.com -v
  python phishing_detector.py https://suspicious.example.com -o json -f report.json
  python phishing_detector.py --batch urls.txt -v
        """,
    )
    p.add_argument("url", nargs="?", help="Target URL to analyse")
    p.add_argument("--batch", "-b", metavar="FILE",
                   help="Analyse URLs from a newline-separated file")
    p.add_argument("--output", "-o", choices=["terminal", "json"], default="terminal")
    p.add_argument("--file", "-f", metavar="PATH",
                   help="Write JSON output to file (JSON mode only)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show per-module flags live during scan")
    p.add_argument("--timeout", "-t", type=int, default=HTTP_TIMEOUT, metavar="SEC")
    p.add_argument("--version", "-V", action="version", version=f"phishing-detector {VERSION}")
    return p


def exit_code(level: str) -> int:
    return {"SAFE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(level, 0)


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.url and not args.batch:
        parser.print_help()
        return 10

    urls: List[str] = []
    if args.url:
        urls.append(args.url)
    if args.batch:
        try:
            with open(args.batch) as fh:
                urls += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            err(f"Batch file not found: {args.batch}")
            return 10

    results  = []
    max_exit = 0

    for url in urls:
        r = analyze(url, verbose=args.verbose, timeout=args.timeout)
        results.append(r)
        if args.output == "terminal":
            render_report(r)
        max_exit = max(max_exit, exit_code(r.level))

    if args.output == "json":
        payload = [r.to_dict() for r in results] if len(results) > 1 else results[0].to_dict()
        if args.file:
            os.makedirs(os.path.dirname(os.path.abspath(args.file)) or ".", exist_ok=True)
            with open(args.file, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            ok(f"Report saved → {args.file}")
        else:
            print(json.dumps(payload, indent=2, default=str))

    return max_exit


if __name__ == "__main__":
    sys.exit(main())
