# phishing-detector

**Modular phishing page analysis toolkit** — static HTML/JS analysis, DNS/WHOIS checks,
SSL certificate inspection, and favicon fingerprinting combined into a weighted risk score.

[![CI](https://github.com/LaxenTgit/phishing-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/LaxenTgit/phishing-detector/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Features

| Module | What it checks |
|--------|---------------|
| **HTML analyzer** | Title/brand domain mismatch, external form POST targets, suspicious PHP endpoints, JS obfuscation, hidden iframes, meta-refresh redirects, kit artifacts (`.zip` references), copyright mismatch |
| **DNS / WHOIS** | Domain age, registrar abuse patterns, subdomain brand injection, typosquatting, URL-in-raw-IP detection |
| **SSL checker** | Certificate age, short-lived validity, free CA abuse (Let's Encrypt, ZeroSSL), SAN hostname mismatch, wildcard scope |
| **Favicon** | External favicon host, brand hash fingerprinting (MD5 + MMH3/Shodan-compatible) |
| **Scorer** | Configurable weighted aggregation → 0–100 risk score, 5 severity levels |

---

## Install

```bash
git clone https://github.com/LaxenTgit/phishing-detector
cd phishing-detector
pip install -e .
```

**Requirements:** Python 3.10+

---

## Usage

```bash
# Basic scan
phishing-detector https://suspicious-site.example.com

# Verbose — show per-module flags live
phishing-detector https://suspicious-site.example.com -v

# JSON report to stdout
phishing-detector https://suspicious-site.example.com -o json

# JSON report saved to file
phishing-detector https://suspicious-site.example.com -o json -f reports/result.json

# Batch scan from file (one URL per line)
phishing-detector --batch urls.txt -v

# Custom timeout
phishing-detector https://slow-site.example.com -t 20
```

### As a library

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector(verbose=False)
result   = detector.analyze("https://paypa1-secure.com")

print(result.level)        # RiskLevel.CRITICAL
print(result.total_score)  # 82.5
print(result.all_flags)    # list of human-readable indicators
```

---

## Output

```
──────────────────────────────────────────────────────
  phishing-detector  |  https://paypa1-secure.com
──────────────────────────────────────────────────────
[*] Fetching page...
[*] Analysing HTML & JavaScript...
[*] Checking domain registration...
[*] Inspecting SSL certificate...
[*] Fingerprinting favicon...

══════════════════════════════════════════════════════
  RISK REPORT
──────────────────────────────────────────────────────
  URL      https://paypa1-secure.com
  Score    82.5/100
  Level    CRITICAL
──────────────────────────────────────────────────────
  Module      Raw    Weight   Contrib
  ──────────  ─────  ───────  ────────
  html           80      35%      28.0
  dns            95      30%      28.5
  ssl            55      20%      11.0
  favicon        50      15%       7.5
──────────────────────────────────────────────────────
  Flags (7):
    • Domain is 2 day(s) old — extremely new
    • Domain 'paypa1-secure.com' appears to typosquat 'paypal'
    • Page title claims to be 'paypal' but domain is 'paypa1-secure.com'
    • Form submits to external domain: evil.ru
    • Suspicious form action endpoint: 'gate.php'
    • Certificate issued by free CA 'Let's Encrypt' — widely abused
    • Short-lived certificate (90-day validity)
══════════════════════════════════════════════════════
```

### Exit codes

| Code | Level |
|------|-------|
| `0`  | SAFE / LOW |
| `1`  | MEDIUM |
| `2`  | HIGH |
| `3`  | CRITICAL |
| `10` | Usage error |

Useful for scripting: `phishing-detector $URL && echo "clean"`.

---

## Architecture

```
src/phishing_detector/
├── __init__.py          # Public API — PhishingDetector, __version__
├── __main__.py          # python -m phishing_detector entry
├── cli.py               # Argument parsing, report rendering, exit codes
├── core.py              # PhishingDetector orchestrator class
├── config.py            # All constants and tuneable weights
├── models.py            # Typed dataclasses for every module result
├── utils/
│   ├── logger.py        # Colour-aware structured logger
│   └── url_utils.py     # URL normalisation, domain extraction
└── modules/
    ├── fetcher.py        # HTTP retrieval + redirect chain
    ├── html_analyzer.py  # Static HTML/JS analysis
    ├── dns_whois.py      # DNS resolution + WHOIS age checks
    ├── ssl_checker.py    # TLS certificate inspection
    ├── favicon.py        # Favicon download + hash fingerprinting
    └── scorer.py         # Weighted aggregation engine
```

---

## Extending

1. Create `src/phishing_detector/modules/my_module.py`
2. Define `analyze(...) -> ModuleResult` returning `.flags`, `.score`, `.errors`
3. Add it to `PhishingDetector.analyze()` in `core.py`
4. Register its weight in `config.py → ModuleWeights`
5. Add it to `scorer.py → module_map`

Possible extensions:
- **VirusTotal / URLhaus API** — external threat intelligence lookup
- **Playwright screenshot** — visual similarity scoring against brand pages
- **PhishTank feed** — blocklist cross-reference
- **Telegram/Discord alert bot** — real-time notification on CRITICAL hits
- **Web UI** — Flask/FastAPI frontend for non-CLI users

---

## Development

```bash
pip install -e ".[dev]"   # install with dev deps
pytest                    # run tests
ruff check src/ tests/    # lint
mypy src/phishing_detector # type check
```
## License

MIT — see [LICENSE](LICENSE).
