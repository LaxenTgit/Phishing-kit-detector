#!/usr/bin/env python3
"""HTTP retrieval with redirect chain analysis and security header checks."""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import HTTP_TIMEOUT, HTTP_USER_AGENT, HTTP_HEADERS
from ..models import FetchResult
from ..utils.url_utils import extract_domain


def fetch(url: str, timeout: int = HTTP_TIMEOUT) -> FetchResult:
    """Fetch a URL and analyse the response for phishing indicators."""
    result = FetchResult()
    session = requests.Session()
    session.headers.update({"User-Agent": HTTP_USER_AGENT, **HTTP_HEADERS})

    retry = Retry(
        total=2, backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        result.success = True
        result.status_code = r.status_code
        result.html = r.text
        result.response_headers = dict(r.headers)
        result.final_url = r.url
        result.content_type = r.headers.get("Content-Type", "")
        result.redirect_chain = [x.url for x in r.history]

        orig_domain = extract_domain(url)
        final_domain = extract_domain(r.url)
        if orig_domain != final_domain:
            result.flag(
                f"Domain changed after redirect: {orig_domain} → {final_domain}", 10
            )
        if len(result.redirect_chain) > 3:
            result.flag(
                f"Excessive redirect chain ({len(result.redirect_chain)} hops)", 10
            )
        if r.status_code >= 400:
            result.flag(f"HTTP {r.status_code} response", 5)

        headers_lc = {k.lower() for k in r.headers}
        missing = {
            "x-frame-options", "content-security-policy", "x-content-type-options"
        } - headers_lc
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
