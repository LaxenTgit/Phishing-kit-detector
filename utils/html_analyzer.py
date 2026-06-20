"""
HTML/JS static analysis module.
Parses page source for phishing kit indicators:
  - Brand/title domain mismatch
  - Suspicious form actions
  - JS obfuscation patterns
  - Hidden iframes, meta refresh, kit artifacts
  - Hotlinked resources from legit domains
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from phishing_detector.config import (
    BRAND_KEYWORDS,
    JS_OBFUSCATION_PATTERNS,
    SUSPICIOUS_FORM_ENDPOINTS,
)
from phishing_detector.models import HTMLResult
from phishing_detector.utils import extract_domain, get_logger

logger = get_logger(__name__)


def analyze(html: str, original_url: str, final_url: str) -> HTMLResult:
    result  = HTMLResult()
    soup    = BeautifulSoup(html, "html.parser")
    domain  = extract_domain(final_url)

    _check_title(soup, domain, result)
    _check_forms(soup, domain, html, result)
    _check_external_resources(soup, domain, result)
    _check_js_obfuscation(soup, result)
    _check_kit_artifacts(html, result)
    _check_hidden_iframes(soup, result)
    _check_meta_refresh(soup, result)
    _check_copyright_mismatch(soup, domain, result)

    result.title        = _get_title(soup)
    result.form_count   = len(soup.find_all("form"))
    result.script_count = len(soup.find_all("script"))
    result.iframe_count = len(soup.find_all("iframe"))

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_title(soup: BeautifulSoup) -> str:
    tag = soup.find("title")
    return tag.get_text(strip=True) if tag else ""


def _check_title(soup: BeautifulSoup, domain: str, result: HTMLResult) -> None:
    title = _get_title(soup).lower()
    for brand in BRAND_KEYWORDS:
        if brand in title and brand not in domain:
            result.add_flag(
                f"Page title claims to be '{brand}' but domain is '{domain}'", 20
            )
            return  # one brand match is enough


def _check_forms(soup: BeautifulSoup, domain: str, html: str, result: HTMLResult) -> None:
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()

        # External POST target
        if action:
            action_parsed = urlparse(action)
            action_domain = action_parsed.netloc
            if action_domain and action_domain != domain:
                result.add_flag(f"Form submits to external domain: {action_domain}", 25)

            # Suspicious PHP endpoint
            for pattern in SUSPICIOUS_FORM_ENDPOINTS:
                if re.search(pattern, action, re.IGNORECASE):
                    result.add_flag(f"Suspicious form action endpoint: '{action}'", 15)
                    break
        else:
            # Empty action — credentials likely exfil'd via JS
            if form.find("input", {"type": "password"}):
                result.add_flag(
                    "Password field present in form with empty action — JS-based credential theft likely",
                    20,
                )

        # Credential harvest: username + password combo in a single form
        has_pw   = bool(form.find("input", {"type": "password"}))
        has_user = bool(
            form.find("input", attrs={"name": re.compile(r"user|email|login|account", re.I)})
        )
        if has_pw and has_user:
            result.add_flag("Credential harvest form detected (username + password fields)", 10)
            return  # flag once per page, not per form


def _check_external_resources(soup: BeautifulSoup, domain: str, result: HTMLResult) -> None:
    seen: set[str] = set()
    for tag in soup.find_all(["img", "link", "script"]):
        src = (tag.get("src") or tag.get("href") or "").strip()
        if not src:
            continue
        src_domain = urlparse(src).netloc
        if not src_domain or src_domain == domain or src_domain in seen:
            continue
        for brand in BRAND_KEYWORDS:
            if brand in src_domain:
                result.add_flag(
                    f"Resource hotlinked from brand domain '{src_domain}'", 15
                )
                seen.add(src_domain)
                break


def _check_js_obfuscation(soup: BeautifulSoup, result: HTMLResult) -> None:
    scripts = soup.find_all("script")
    combined = " ".join(s.get_text() for s in scripts if s.get_text())
    hits: set[str] = set()
    for pattern in JS_OBFUSCATION_PATTERNS:
        if re.search(pattern, combined) and pattern not in hits:
            result.add_flag(f"JS obfuscation pattern detected: {pattern}", 10)
            hits.add(pattern)
            if len(hits) >= 3:
                break  # cap to avoid score inflation from one obfuscated blob


def _check_kit_artifacts(html: str, result: HTMLResult) -> None:
    # Phishing kits often leave .zip references (from the kit archive)
    if re.search(r'["\'].*?\.zip["\']', html, re.IGNORECASE):
        result.add_flag("ZIP file reference in HTML source — possible kit upload artifact", 10)

    # PHP mailer include remnants
    if re.search(r'(include|require).*?mailer\.php', html, re.IGNORECASE):
        result.add_flag("PHP mailer include reference found — common in phishing kits", 15)


def _check_hidden_iframes(soup: BeautifulSoup, result: HTMLResult) -> None:
    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").replace(" ", "").lower()
        hidden = (
            "display:none" in style
            or "visibility:hidden" in style
            or iframe.has_attr("hidden")
            or iframe.get("width") == "0"
            or iframe.get("height") == "0"
        )
        if hidden:
            src = iframe.get("src", "N/A")
            result.add_flag(f"Hidden iframe detected (src: {src})", 10)


def _check_meta_refresh(soup: BeautifulSoup, result: HTMLResult) -> None:
    tag = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
    if tag:
        content = tag.get("content", "")
        result.add_flag(f"Meta-refresh redirect present: '{content}'", 10)


def _check_copyright_mismatch(soup: BeautifulSoup, domain: str, result: HTMLResult) -> None:
    text = soup.get_text(separator=" ").lower()
    for brand in BRAND_KEYWORDS:
        patterns = [f"© {brand}", f"copyright {brand}", f"{brand}, inc", f"{brand} llc"]
        if any(p in text for p in patterns) and brand not in domain:
            result.add_flag(
                f"Page claims '{brand}' copyright but domain is '{domain}'", 15
            )
            return
