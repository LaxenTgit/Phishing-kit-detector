"""
Shared result types — every module returns a typed dataclass, never a raw dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    SAFE     = "SAFE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN  = "UNKNOWN"

    @property
    def color_code(self) -> str:
        return {
            "SAFE":     "\033[92m",
            "LOW":      "\033[93m",
            "MEDIUM":   "\033[93m",
            "HIGH":     "\033[91m",
            "CRITICAL": "\033[91m\033[1m",
            "UNKNOWN":  "\033[0m",
        }.get(self.value, "\033[0m")


@dataclass
class ModuleResult:
    """Base class for all module results."""
    flags:  List[str] = field(default_factory=list)
    score:  int       = 0
    errors: List[str] = field(default_factory=list)

    def add_flag(self, message: str, points: int) -> None:
        self.flags.append(message)
        self.score = min(self.score + points, 100)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flags":  self.flags,
            "score":  self.score,
            "errors": self.errors,
        }


@dataclass
class FetchResult(ModuleResult):
    success:        bool            = False
    status_code:    Optional[int]   = None
    html:           str             = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    final_url:      str             = ""
    redirect_chain: List[str]       = field(default_factory=list)
    content_type:   str             = ""
    content_length: int             = 0

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "success":      self.success,
            "status_code":  self.status_code,
            "final_url":    self.final_url,
            "redirect_chain": self.redirect_chain,
            "content_type": self.content_type,
            "content_length": self.content_length,
        })
        return base


@dataclass
class HTMLResult(ModuleResult):
    title:        str = ""
    form_count:   int = 0
    script_count: int = 0
    iframe_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "title":        self.title,
            "form_count":   self.form_count,
            "script_count": self.script_count,
            "iframe_count": self.iframe_count,
        })
        return base


@dataclass
class DNSResult(ModuleResult):
    domain:           str           = ""
    ip:               Optional[str] = None
    age_days:         Optional[int] = None
    creation_date:    Optional[str] = None
    registrar:        Optional[str] = None
    whois_protected:  bool          = False

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "domain":          self.domain,
            "ip":              self.ip,
            "age_days":        self.age_days,
            "creation_date":   self.creation_date,
            "registrar":       self.registrar,
            "whois_protected": self.whois_protected,
        })
        return base


@dataclass
class SSLResult(ModuleResult):
    scheme:           str           = ""
    issuer_org:       Optional[str] = None
    cert_age_days:    Optional[int] = None
    cert_valid_days:  Optional[int] = None
    issued:           Optional[str] = None
    expires:          Optional[str] = None
    san:              List[str]     = field(default_factory=list)
    wildcard:         bool          = False

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "scheme":          self.scheme,
            "issuer_org":      self.issuer_org,
            "cert_age_days":   self.cert_age_days,
            "cert_valid_days": self.cert_valid_days,
            "issued":          self.issued,
            "expires":         self.expires,
            "san":             self.san,
            "wildcard":        self.wildcard,
        })
        return base


@dataclass
class FaviconResult(ModuleResult):
    favicon_url:    Optional[str] = None
    favicon_hash:   Optional[str] = None
    matched_brand:  Optional[str] = None
    external_host:  bool          = False

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "favicon_url":   self.favicon_url,
            "favicon_hash":  self.favicon_hash,
            "matched_brand": self.matched_brand,
            "external_host": self.external_host,
        })
        return base


@dataclass
class ScoreBreakdown:
    module:       str   = ""
    raw_score:    int   = 0
    weight:       float = 0.0
    contribution: float = 0.0


@dataclass
class AnalysisResult:
    """Top-level result returned by PhishingDetector.analyze()."""
    url:        str            = ""
    final_url:  str            = ""
    timestamp:  str            = ""
    total_score: float         = 0.0
    level:      RiskLevel      = RiskLevel.UNKNOWN
    all_flags:  List[str]      = field(default_factory=list)
    breakdown:  List[ScoreBreakdown] = field(default_factory=list)

    # Module results
    fetch:   Optional[FetchResult]   = None
    html:    Optional[HTMLResult]    = None
    dns:     Optional[DNSResult]     = None
    ssl:     Optional[SSLResult]     = None
    favicon: Optional[FaviconResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":         self.url,
            "final_url":   self.final_url,
            "timestamp":   self.timestamp,
            "total_score": self.total_score,
            "level":       self.level.value,
            "all_flags":   self.all_flags,
            "breakdown": [
                {
                    "module":       b.module,
                    "raw_score":    b.raw_score,
                    "weight":       b.weight,
                    "contribution": b.contribution,
                }
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
