from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from phishing_detector.config import FREE_CA_ISSUERS
from phishing_detector.models import SSLResult
from phishing_detector.utils import extract_domain, get_logger

logger = get_logger(__name__)

_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def analyze(url: str) -> SSLResult:
    result = SSLResult()
    parsed = urlparse(url)
    result.scheme = parsed.scheme

    if parsed.scheme == "http":
        result.add_flag("Site is served over plain HTTP — no encryption", 20)
        return result

    hostname = extract_domain(url)
    port = int(parsed.port or 443)

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()

        _check_dates(cert, result)
        _check_issuer(cert, result)
        _check_san(cert, hostname, result)

    except ssl.SSLCertVerificationError as exc:
        result.add_flag(f"SSL certificate verification failed: {exc}", 30)
    except ssl.SSLError as exc:
        result.add_flag(f"SSL error: {exc}", 20)
    except ConnectionRefusedError:
        result.add_flag("Connection refused on port 443", 5)
    except socket.timeout:
        result.add_flag("SSL handshake timed out", 5)
    except Exception as exc:  # noqa: BLE001
        result.add_error(f"SSL check failed: {exc}")
        logger.debug("SSL exception for %s: %s", hostname, exc, exc_info=True)

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _parse_cert_date(raw: str) -> datetime:
    return datetime.strptime(raw, _DATE_FMT).replace(tzinfo=timezone.utc)


def _check_dates(cert: dict, result: SSLResult) -> None:
    try:
        not_before = _parse_cert_date(cert["notBefore"])
        not_after  = _parse_cert_date(cert["notAfter"])
        now        = datetime.now(timezone.utc)

        age_days   = (now - not_before).days
        valid_days = (not_after - not_before).days

        result.issued          = not_before.isoformat()
        result.expires         = not_after.isoformat()
        result.cert_age_days   = age_days
        result.cert_valid_days = valid_days

        if age_days < 3:
            result.add_flag(f"Certificate issued {age_days} day(s) ago — extremely fresh", 20)
        elif age_days < 14:
            result.add_flag(f"Certificate issued {age_days} day(s) ago — very recently issued", 12)
        elif age_days < 30:
            result.add_flag(f"Certificate is only {age_days} days old", 6)

        # Short-lived certs are cheap and fast to issue — favoured by phishing ops
        if valid_days <= 90:
            result.add_flag(
                f"Short-lived certificate ({valid_days}-day validity) — "
                "commonly used in phishing infrastructure",
                10,
            )

    except (KeyError, ValueError) as exc:
        result.add_error(f"Could not parse certificate dates: {exc}")


def _check_issuer(cert: dict, result: SSLResult) -> None:
    issuer_fields = {k: v for item in cert.get("issuer", []) for k, v in item}
    org = issuer_fields.get("organizationName", "")
    result.issuer_org = org or None

    if any(ca in org.lower() for ca in FREE_CA_ISSUERS):
        result.add_flag(
            f"Certificate issued by free CA '{org}' — widely abused for phishing domains", 8
        )


def _check_san(cert: dict, hostname: str, result: SSLResult) -> None:
    san_list = [v for _, v in cert.get("subjectAltName", [])]
    result.san = san_list

    wildcard_domains = [s for s in san_list if s.startswith("*.")]
    result.wildcard  = bool(wildcard_domains)

    if result.wildcard:
        result.add_flag(
            f"Wildcard certificate in use — covers all subdomains: {wildcard_domains}", 5
        )
        return  # wildcard implies hostname coverage — no mismatch possible

    if san_list and hostname not in san_list:
        result.add_flag(
            f"Hostname '{hostname}' not found in certificate SAN list — possible MitM or misconfiguration",
            20,
        )
