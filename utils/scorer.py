from __future__ import annotations

from phishing_detector.config import WEIGHTS, THRESHOLDS
from phishing_detector.models import (
    AnalysisResult,
    RiskLevel,
    ScoreBreakdown,
)


def calculate(result: AnalysisResult) -> None:
    """
    Mutates result in-place:
      - sets result.total_score
      - sets result.level
      - populates result.all_flags
      - populates result.breakdown
    """
    module_map = {
        "html":    result.html,
        "dns":     result.dns,
        "ssl":     result.ssl,
        "favicon": result.favicon,
    }
    weights = WEIGHTS.as_dict()

    total      = 0.0
    all_flags  = []
    breakdown  = []

    for name, module_result in module_map.items():
        weight    = weights[name]
        raw_score = module_result.score if module_result else 0
        contrib   = round(raw_score * weight, 2)
        total    += contrib

        breakdown.append(ScoreBreakdown(
            module=name,
            raw_score=raw_score,
            weight=weight,
            contribution=contrib,
        ))

        if module_result:
            all_flags.extend(module_result.flags)

    result.total_score = round(total, 1)
    result.level       = RiskLevel(THRESHOLDS.level_for(result.total_score))
    result.all_flags   = all_flags
    result.breakdown   = breakdown
