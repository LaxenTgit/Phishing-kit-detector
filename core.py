from __future__ import annotations

import sys
from datetime import datetime, timezone

from phishing_detector.models import AnalysisResult
from phishing_detector.modules import fetcher, html_analyzer, dns_whois, ssl_checker, favicon, scorer
from phishing_detector.utils import get_logger, normalise_url, step, warn, error

logger = get_logger(__name__)


class PhishingDetector:
    """
    Main analysis class. Instantiate once, call .analyze() per URL.

    Example::

        detector = PhishingDetector(verbose=True)
        result   = detector.analyze("https://paypa1-secure.com")
        print(result.level, result.total_score)
    """

    def __init__(self, verbose: bool = False, timeout: int | None = None) -> None:
        self.verbose = verbose
        if timeout:
            # Allow caller to override HTTP timeout at runtime
            from phishing_detector import config
            object.__setattr__(config.HTTP, "timeout", timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, url: str) -> AnalysisResult:
        url = normalise_url(url)
        result = AnalysisResult(
            url=url,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        print(f"\n{'─'*54}")
        print(f"  phishing-detector  |  {url}")
        print(f"{'─'*54}")

        # 1 — Fetch
        step("Fetching page...")
        fetch_result = fetcher.fetch(url)
        result.fetch = fetch_result

        if not fetch_result.success:
            for err in fetch_result.errors:
                error(err)
            warn("Fetch failed — running DNS/SSL checks only.")

        result.final_url = fetch_result.final_url or url

        # 2 — HTML analysis (only if we got HTML)
        step("Analysing HTML & JavaScript...")
        if fetch_result.html:
            result.html = html_analyzer.analyze(
                fetch_result.html,
                url,
                result.final_url,
            )
            if self.verbose:
                self._print_flags("HTML", result.html.flags)
        else:
            from phishing_detector.models import HTMLResult
            result.html = HTMLResult()
            result.html.add_error("No HTML content to analyse")

        # 3 — DNS / WHOIS
        step("Checking domain registration...")
        result.dns = dns_whois.analyze(url)
        if self.verbose:
            self._print_flags("DNS", result.dns.flags)

        # 4 — SSL
        step("Inspecting SSL certificate...")
        result.ssl = ssl_checker.analyze(result.final_url or url)
        if self.verbose:
            self._print_flags("SSL", result.ssl.flags)

        # 5 — Favicon
        step("Fingerprinting favicon...")
        result.favicon = favicon.analyze(fetch_result.html or "", url)
        if self.verbose:
            self._print_flags("FAV", result.favicon.flags)

        # 6 — Score
        scorer.calculate(result)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _print_flags(label: str, flags: list[str]) -> None:
        for flag in flags:
            print(f"      \033[2m[{label}]\033[0m {flag}")
