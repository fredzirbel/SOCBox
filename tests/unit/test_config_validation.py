import pytest

from socbox.config import _validate_scoring_config


def _base_config() -> dict:
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


def test_validate_scoring_config_accepts_valid_config() -> None:
    _validate_scoring_config(_base_config())


def test_validate_scoring_config_rejects_bad_weight_sum() -> None:
    cfg = _base_config()
    cfg["scoring"]["weights"]["download"] = 14
    with pytest.raises(ValueError, match="must sum to 100.0"):
        _validate_scoring_config(cfg)


def test_validate_scoring_config_rejects_bad_blend_sum() -> None:
    cfg = _base_config()
    cfg["scoring"]["blend"] = {"analyzer_weight": 0.5, "feed_weight": 0.6}
    with pytest.raises(ValueError, match="must equal 1.0"):
        _validate_scoring_config(cfg)


def test_validate_scoring_config_rejects_inverted_thresholds() -> None:
    cfg = _base_config()
    cfg["scoring"]["thresholds"] = {"safe": 70, "malicious": 60}
    with pytest.raises(ValueError, match="must be less than"):
        _validate_scoring_config(cfg)
