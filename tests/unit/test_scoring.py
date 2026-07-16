from socbox.models import AnalyzerResult, AnalyzerStatus, FeedResult, RiskCategory
from socbox.scoring import calculate_score, score_breakdown


def _config() -> dict:
    return {
        "scoring": {
            "thresholds": {"safe": 25, "malicious": 60},
            "blend": {"analyzer_weight": 0.45, "feed_weight": 0.55},
            "feed_weights": {
                "VirusTotal": 40,
                "Google Safe Browsing": 35,
                "AbuseIPDB": 25,
            },
        }
    }


def test_threat_feed_analyzer_not_double_counted_when_feed_blend_active() -> None:
    results = [
        AnalyzerResult(
            analyzer_name="URL Lexical Analysis",
            status=AnalyzerStatus.COMPLETED,
            score=0.0,
            max_weight=100.0,
        ),
        AnalyzerResult(
            analyzer_name="Threat Feed Integration",
            status=AnalyzerStatus.COMPLETED,
            score=100.0,
            max_weight=100.0,
        ),
    ]
    feed_results = [
        FeedResult(
            feed_name="VirusTotal",
            matched=True,
            details="10 malicious, 0 suspicious",
            raw_response={"malicious": 10, "suspicious": 0},
        )
    ]

    score, category, confidence = calculate_score(results, feed_results, _config())

    # Without de-duplication this would be 77.5.
    assert score == 65.0
    assert category == RiskCategory.MALICIOUS
    assert confidence == 100.0


def test_score_breakdown_aligns_with_verdict_and_excludes_feed_analyzer() -> None:
    results = [
        AnalyzerResult(
            analyzer_name="URL Lexical Analysis",
            status=AnalyzerStatus.COMPLETED,
            score=40.0,
            max_weight=20.0,
        ),
        AnalyzerResult(
            analyzer_name="Threat Feed Integration",
            status=AnalyzerStatus.COMPLETED,
            score=100.0,
            max_weight=20.0,
        ),
    ]
    feed_results = [
        FeedResult(
            feed_name="VirusTotal",
            matched=True,
            details="10 malicious",
            raw_response={"malicious": 10, "suspicious": 0},
        )
    ]

    bd = score_breakdown(results, feed_results, _config())
    score, _, _ = calculate_score(results, feed_results, _config())

    # The feed analyzer is shown as a separate blended line, not a peer row.
    names = [a["name"] for a in bd["analyzers"]]
    assert "Threat Feed Integration" not in names
    assert bd["threat_feeds"] is not None
    assert bd["threat_feeds"]["matched_feeds"] == ["VirusTotal"]

    # Breakdown composite equals the verdict composite (single source of truth).
    assert bd["composite"] == score
