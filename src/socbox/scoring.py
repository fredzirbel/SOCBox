"""Central scoring engine for SOC Box.

Classifies URLs into a 3-tier system (Safe / Uncertain / Malicious) with a
confidence percentage that reflects how strongly the evidence agrees on the
classification.  Threat feed matches are treated as weighted signals - not
binary overrides - so a single low-confidence hit is distinguished from
unanimous feed agreement.
"""

from __future__ import annotations

from typing import Any

from socbox.models import AnalyzerResult, AnalyzerStatus, FeedResult, RiskCategory

# Default per-feed weights used when config does not specify them.
_DEFAULT_FEED_WEIGHTS: dict[str, float] = {
    "VirusTotal": 40.0,
    "Google Safe Browsing": 35.0,
    "AbuseIPDB": 25.0,
}

_THREAT_FEED_ANALYZER_NAME = "Threat Feed Integration"


def _composite_parts(
    results: list[AnalyzerResult],
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Compute the shared intermediate scoring values.

    Single source of truth for the composite math so the verdict
    (``calculate_score``) and the analyst-facing breakdown
    (``score_breakdown``) can never diverge. Mirrors the original Step 1-3
    pipeline. Assumes at least one completed analyzer.

    Returns:
        Dict with completed, analyzer_inputs, total_weight, raw_score,
        feed_signal, analyzer_blend, feed_blend, pre_floor, composite.
    """
    completed = [r for r in results if r.status == AnalyzerStatus.COMPLETED]

    scoring_cfg = config.get("scoring", {})
    blend = scoring_cfg.get("blend", {})
    analyzer_blend = blend.get("analyzer_weight", 0.45)
    feed_blend = blend.get("feed_weight", 0.55)

    # Exclude the Threat Feed analyzer from the analyzer average when feeds are
    # blended separately, so the same evidence is not counted twice.
    analyzer_inputs = list(completed)
    if feed_blend > 0 and feed_results:
        filtered = [
            r for r in completed if r.analyzer_name != _THREAT_FEED_ANALYZER_NAME
        ]
        analyzer_inputs = filtered or list(completed)

    total_weight = sum(r.max_weight for r in analyzer_inputs)
    raw_score = 0.0
    if total_weight > 0:
        for result in analyzer_inputs:
            raw_score += result.score * (result.max_weight / total_weight)

    feed_signal = _compute_feed_signal(feed_results, config)

    # If no feeds are configured at all, give all weight to analyzers.
    if len(feed_results) == 0:
        analyzer_blend = 1.0
        feed_blend = 0.0

    pre_floor = (raw_score * analyzer_blend) + (feed_signal * feed_blend)
    pre_floor = min(100.0, max(0.0, pre_floor))
    composite = _apply_feed_floor(pre_floor, feed_results, config)

    return {
        "completed": completed,
        "analyzer_inputs": analyzer_inputs,
        "total_weight": total_weight,
        "raw_score": raw_score,
        "feed_signal": feed_signal,
        "analyzer_blend": analyzer_blend,
        "feed_blend": feed_blend,
        "pre_floor": pre_floor,
        "composite": composite,
    }


def calculate_score(
    results: list[AnalyzerResult],
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> tuple[float, RiskCategory, float]:
    """Aggregate analyzer results into a classification and confidence.

    The pipeline is:
      1. Weighted average of completed analyzer scores (0-100).
      2. Graduated feed signal (0-100) based on which feeds matched.
      3. Composite score blending analyzers and feeds.
      4. 3-tier classification via configurable thresholds.
      5. Confidence percentage reflecting signal agreement.

    Args:
        results: List of AnalyzerResult from all analyzers.
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        Tuple of (composite_score, risk_category, confidence_pct).
    """
    completed = [r for r in results if r.status == AnalyzerStatus.COMPLETED]

    if not completed:
        has_match = any(fr.matched for fr in feed_results)
        if has_match:
            return 100.0, RiskCategory.MALICIOUS, 60.0
        return 0.0, RiskCategory.SAFE, 50.0

    parts = _composite_parts(results, feed_results, config)
    composite = parts["composite"]

    # 3-tier classification via configurable thresholds.
    thresholds = config.get("scoring", {}).get("thresholds", {})
    safe_max = thresholds.get("safe", 25)
    malicious_min = thresholds.get("malicious", 60)

    if composite <= safe_max:
        category = RiskCategory.SAFE
    elif composite >= malicious_min:
        category = RiskCategory.MALICIOUS
    else:
        category = RiskCategory.UNCERTAIN

    confidence = _calculate_confidence(
        completed, composite, parts["feed_signal"], category, thresholds,
    )

    return round(composite, 1), category, confidence


def score_breakdown(
    results: list[AnalyzerResult],
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Per-analyzer contribution breakdown for the analyst-facing table.

    Uses the same ``_composite_parts`` math as the verdict. Each completed,
    non-feed analyzer's contribution to the 0-100 composite is
    ``score * normalized_weight * analyzer_blend``; threat feeds contribute
    ``feed_signal * feed_blend`` as one blended line (never averaged as a
    peer analyzer).

    Returns:
        Dict with: analyzers (sorted by contribution desc), threat_feeds,
        analyzer_blend, feed_blend, analyzer_total, feed_total, composite,
        floor_applied.
    """
    completed = [r for r in results if r.status == AnalyzerStatus.COMPLETED]
    if not completed:
        composite = 100.0 if any(fr.matched for fr in feed_results) else 0.0
        return {
            "analyzers": [], "threat_feeds": None,
            "analyzer_blend": 1.0, "feed_blend": 0.0,
            "analyzer_total": 0.0, "feed_total": 0.0,
            "composite": composite, "floor_applied": None,
        }

    parts = _composite_parts(results, feed_results, config)
    total_weight = parts["total_weight"]
    ab = parts["analyzer_blend"]
    fb = parts["feed_blend"]
    feed_signal = parts["feed_signal"]

    analyzers = []
    for r in parts["analyzer_inputs"]:
        nw = (r.max_weight / total_weight) if total_weight > 0 else 0.0
        analyzers.append({
            "name": r.analyzer_name,
            "raw_score": round(r.score, 1),
            "max_weight": round(r.max_weight, 1),
            "normalized_weight": round(nw, 3),
            "contribution": round(r.score * nw * ab, 2),
        })
    analyzers.sort(key=lambda a: a["contribution"], reverse=True)

    threat_feeds = None
    if feed_results:
        threat_feeds = {
            "feed_signal": round(feed_signal, 1),
            "contribution": round(feed_signal * fb, 2),
            "matched_feeds": [fr.feed_name for fr in feed_results if fr.matched],
        }

    floor_applied = (
        round(parts["composite"], 1)
        if parts["composite"] > parts["pre_floor"] + 0.05 else None
    )

    return {
        "analyzers": analyzers,
        "threat_feeds": threat_feeds,
        "analyzer_blend": ab,
        "feed_blend": fb,
        "analyzer_total": round(sum(a["contribution"] for a in analyzers), 2),
        "feed_total": round(feed_signal * fb, 2),
        "composite": round(parts["composite"], 1),
        "floor_applied": floor_applied,
    }


def _compute_feed_signal(
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> float:
    """Compute a 0-100 feed signal with severity-aware scaling.

    The signal accounts for:
      - Which feeds matched (weighted by reliability).
      - How many VT engines flagged the URL (severity scaling).
      - Non-matching feeds only dilute the signal partially - absence
        of data in GSB/AbuseIPDB should not cancel a strong VT hit.

    Args:
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        Feed signal strength on a 0-100 scale.
    """
    configured_weights = (
        config.get("scoring", {}).get("feed_weights", _DEFAULT_FEED_WEIGHTS)
    )

    total_feed_weight = 0.0
    matched_feed_weight = 0.0
    vt_severity_boost = 0.0

    for fr in feed_results:
        w = configured_weights.get(fr.feed_name, 30.0)
        total_feed_weight += w
        if fr.matched:
            matched_feed_weight += w

            # VirusTotal severity scaling: more detections = stronger signal
            if fr.feed_name == "VirusTotal" and fr.raw_response:
                malicious = fr.raw_response.get("malicious", 0)
                suspicious = fr.raw_response.get("suspicious", 0)
                detections = malicious + suspicious

                # Scale: 3-5 detections = mild boost, 10+ = strong, 20+ = maximum
                if detections >= 20:
                    vt_severity_boost = 50.0
                elif detections >= 10:
                    vt_severity_boost = 40.0
                elif detections >= 5:
                    vt_severity_boost = 25.0
                elif detections >= 3:
                    vt_severity_boost = 10.0

    if total_feed_weight <= 0:
        return 0.0

    base_signal = (matched_feed_weight / total_feed_weight) * 100.0

    # Combine: base signal + VT severity boost, capped at 100
    return min(100.0, base_signal + vt_severity_boost)


def _apply_feed_floor(
    composite: float,
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> float:
    """Enforce a minimum composite score when a feed has strong detections.

    New phishing campaigns are typically flagged by VirusTotal long before
    Google Safe Browsing or AbuseIPDB index them.  Without a floor, the
    absence of data from those feeds dilutes the VT signal enough to push
    clearly malicious URLs into the "Safe" zone.

    Floors (based on VT detection count):
      - 20+ detections → composite floor 75 (Malicious)
      - 10+ detections → composite floor 65 (Malicious)
      - 5+  detections → composite floor 40 (Uncertain)
      - 3+  detections → composite floor 30 (Uncertain)

    Args:
        composite: The current composite score.
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        The composite score, raised to the floor if applicable.
    """
    for fr in feed_results:
        if fr.feed_name == "VirusTotal" and fr.matched and fr.raw_response:
            malicious = fr.raw_response.get("malicious", 0)
            suspicious = fr.raw_response.get("suspicious", 0)
            detections = malicious + suspicious

            if detections >= 20:
                composite = max(composite, 75.0)
            elif detections >= 10:
                composite = max(composite, 65.0)
            elif detections >= 5:
                composite = max(composite, 40.0)
            elif detections >= 3:
                composite = max(composite, 30.0)
            break

    return composite


def _calculate_confidence(
    completed: list[AnalyzerResult],
    composite_score: float,
    feed_signal: float,
    category: RiskCategory,
    thresholds: dict[str, Any],
) -> float:
    """Calculate confidence as a percentage.

    Designed for SOC analysts who need an instant read:
      - **Malicious** → 100%.  If the scoring engine classified it as
        malicious (VT detections, feed matches, etc.) the evidence is
        conclusive and confidence should reflect that.
      - **Safe** → 100%.  All signals agree there's no threat.
      - **Uncertain** → scales between 30-80% based on how far the
        composite is from the decision boundaries.  Low VT hits or
        ambiguous signals produce lower confidence.

    Args:
        completed: List of completed AnalyzerResults.
        composite_score: The blended composite score.
        feed_signal: Feed signal strength (0-100).
        category: The assigned RiskCategory.
        thresholds: Threshold config dict with 'safe' and 'malicious' keys.

    Returns:
        Confidence percentage rounded to 1 decimal.
    """
    if category == RiskCategory.MALICIOUS:
        return 100.0

    if category == RiskCategory.SAFE:
        # A "Safe" verdict is only as trustworthy as the evidence behind it.
        # A full scan (most of the 8 analyzers completed) → high confidence; a
        # thin scan (e.g. the site was down and only lexical ran) → lower
        # confidence, signalling the analyst to look closer rather than trusting
        # a green verdict built on almost no data.
        return round(min(100.0, 40.0 + 8.0 * len(completed)), 1)

    # --- UNCERTAIN zone: scale 30-80% based on evidence strength ---
    safe_max = thresholds.get("safe", 25)
    malicious_min = thresholds.get("malicious", 60)

    # How far into the uncertain zone (0.0 = near safe, 1.0 = near malicious)
    span = max(malicious_min - safe_max, 1)
    position = (composite_score - safe_max) / span
    position = min(1.0, max(0.0, position))

    # Near the boundaries = higher confidence in the *direction*;
    # mid-zone = lowest confidence (most ambiguous)
    # U-shaped curve: confidence is higher at edges, lower in middle
    distance_from_mid = abs(position - 0.5) * 2.0  # 0 at center, 1 at edges
    confidence = 30.0 + distance_from_mid * 50.0

    return round(min(80.0, max(30.0, confidence)), 1)
