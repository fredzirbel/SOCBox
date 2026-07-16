from socbox.analyzers.base import BaseAnalyzer
from socbox.models import AnalyzerResult, AnalyzerStatus
from socbox.scanner import scan_url


class _LexicalAnalyzer(BaseAnalyzer):
    name = "URL Lexical Analysis"
    weight = 20.0

    def analyze(self, url, config, *, browser=None):  # type: ignore[override]
        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=0.0,
            max_weight=self.weight,
            findings=[],
        )


class _HTTPAnalyzer(BaseAnalyzer):
    name = "HTTP Response Analysis"
    weight = 15.0

    def analyze(self, url, config, *, browser=None):  # type: ignore[override]
        raise AssertionError("HTTP analyzer should be skipped in passive mode")


def _config() -> dict:
    return {
        "scoring": {
            "weights": {
                "url_lexical": 20,
                "whois_dns": 15,
                "ssl_tls": 10,
                "http_response": 15,
                "page_content": 15,
                "link_discovery": 10,
                "download": 15,
                "threat_feeds": 0,
            },
            "thresholds": {"safe": 25, "malicious": 60},
            "blend": {"analyzer_weight": 0.45, "feed_weight": 0.55},
            "feed_weights": {
                "VirusTotal": 40,
                "Google Safe Browsing": 35,
                "AbuseIPDB": 25,
            },
        }
    }


def test_passive_mode_skips_network_and_browser_analyzers(monkeypatch) -> None:
    monkeypatch.setattr(
        "socbox.scanner.ALL_ANALYZERS",
        [_LexicalAnalyzer, _HTTPAnalyzer],
    )

    def _fail_get_browser(_url: str):
        raise AssertionError("Browser should not be initialized in passive mode")

    monkeypatch.setattr("socbox.scanner._get_browser", _fail_get_browser)

    report = scan_url(
        "https://example.com",
        _config(),
        passive_only=True,
        screenshot_dir="",
    )

    statuses = {r.analyzer_name: r.status for r in report.analyzer_results}
    assert statuses["URL Lexical Analysis"] == AnalyzerStatus.COMPLETED
    assert statuses["HTTP Response Analysis"] == AnalyzerStatus.SKIPPED
