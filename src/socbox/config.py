"""Configuration loader for SOC Box."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# Mapping of environment variable names to config api_keys entries.
_ENV_KEY_MAP: dict[str, str] = {
    "VIRUSTOTAL_API_KEY": "virustotal",
    "GOOGLE_SAFEBROWSING_API_KEY": "google_safebrowsing",
    "PHISHTANK_API_KEY": "phishtank",
    "URLHAUS_API_KEY": "urlhaus",
    "ABUSEIPDB_API_KEY": "abuseipdb",
    "IPINFO_API_KEY": "ipinfo",
}

_EXPECTED_SCORING_WEIGHT_KEYS = {
    "url_lexical",
    "whois_dns",
    "ssl_tls",
    "http_response",
    "page_content",
    "link_discovery",
    "download",
    "threat_feeds",
}

_EXPECTED_FEED_WEIGHT_KEYS = {
    "VirusTotal",
    "Google Safe Browsing",
    "AbuseIPDB",
}


# Search for config in common locations
_POSSIBLE_CONFIG_PATHS = [
    Path("/app/config/default.yaml"),  # Docker container path
    Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml",  # Source repo path
    Path.cwd() / "config" / "default.yaml",  # Current working directory
]

DEFAULT_CONFIG_PATH = next(
    (p for p in _POSSIBLE_CONFIG_PATHS if p.exists()),
    _POSSIBLE_CONFIG_PATHS[0],
)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _require_numeric(
    container: dict[str, Any],
    key: str,
    *,
    min_value: float | None = None,
) -> float:
    """Return a numeric config value or raise ValueError."""
    value = container.get(key)
    if not isinstance(value, (int, float)):
        raise ValueError(f"Config key '{key}' must be a number")
    value_f = float(value)
    if min_value is not None and value_f < min_value:
        raise ValueError(f"Config key '{key}' must be >= {min_value}")
    return value_f


def _validate_scoring_config(config: dict[str, Any]) -> None:
    """Validate scoring-related config for production safety."""
    scoring = config.get("scoring", {})
    if not isinstance(scoring, dict):
        raise ValueError("Config key 'scoring' must be a mapping")

    weights = scoring.get("weights", {})
    if not isinstance(weights, dict):
        raise ValueError("Config key 'scoring.weights' must be a mapping")

    missing_weight_keys = sorted(_EXPECTED_SCORING_WEIGHT_KEYS - set(weights.keys()))
    extra_weight_keys = sorted(set(weights.keys()) - _EXPECTED_SCORING_WEIGHT_KEYS)
    if missing_weight_keys:
        raise ValueError(
            "Missing scoring.weights keys: " + ", ".join(missing_weight_keys)
        )
    if extra_weight_keys:
        raise ValueError(
            "Unknown scoring.weights keys: " + ", ".join(extra_weight_keys)
        )

    weight_total = 0.0
    for key in _EXPECTED_SCORING_WEIGHT_KEYS:
        weight_total += _require_numeric(weights, key, min_value=0.0)
    if abs(weight_total - 100.0) > 0.001:
        raise ValueError(
            f"scoring.weights must sum to 100.0 (got {weight_total:.3f})"
        )

    thresholds = scoring.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("Config key 'scoring.thresholds' must be a mapping")
    safe_threshold = _require_numeric(thresholds, "safe", min_value=0.0)
    malicious_threshold = _require_numeric(thresholds, "malicious", min_value=0.0)
    if safe_threshold >= malicious_threshold:
        raise ValueError(
            "scoring.thresholds.safe must be less than scoring.thresholds.malicious"
        )

    blend = scoring.get("blend", {})
    if not isinstance(blend, dict):
        raise ValueError("Config key 'scoring.blend' must be a mapping")
    analyzer_weight = _require_numeric(blend, "analyzer_weight", min_value=0.0)
    feed_weight = _require_numeric(blend, "feed_weight", min_value=0.0)
    if abs((analyzer_weight + feed_weight) - 1.0) > 0.001:
        raise ValueError(
            "scoring.blend.analyzer_weight + scoring.blend.feed_weight must equal 1.0"
        )

    feed_weights = scoring.get("feed_weights", {})
    if not isinstance(feed_weights, dict):
        raise ValueError("Config key 'scoring.feed_weights' must be a mapping")
    missing_feed_weight_keys = sorted(_EXPECTED_FEED_WEIGHT_KEYS - set(feed_weights.keys()))
    extra_feed_weight_keys = sorted(set(feed_weights.keys()) - _EXPECTED_FEED_WEIGHT_KEYS)
    if missing_feed_weight_keys:
        raise ValueError(
            "Missing scoring.feed_weights keys: " + ", ".join(missing_feed_weight_keys)
        )
    if extra_feed_weight_keys:
        raise ValueError(
            "Unknown scoring.feed_weights keys: " + ", ".join(extra_feed_weight_keys)
        )
    feed_weight_total = 0.0
    for key in _EXPECTED_FEED_WEIGHT_KEYS:
        feed_weight_total += _require_numeric(feed_weights, key, min_value=0.0)
    if abs(feed_weight_total - 100.0) > 0.001:
        raise ValueError(
            f"scoring.feed_weights must sum to 100.0 (got {feed_weight_total:.3f})"
        )


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML files.

    Loads the default config, then merges with a local override file
    (config/local.yaml) or a user-specified config path.

    Args:
        config_path: Optional path to a config YAML file. If provided,
            it is merged on top of the default config.

    Returns:
        Merged configuration dictionary.
    """
    with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Try loading local.yaml as an override
    local_path = DEFAULT_CONFIG_PATH.parent / "local.yaml"
    if local_path.exists():
        with open(local_path, "r", encoding="utf-8") as f:
            local_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, local_config)

    # Apply user-specified config on top
    if config_path is not None:
        user_path = Path(config_path)
        if user_path.exists():
            with open(user_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)

    # Overlay API keys from environment variables (highest priority).
    # This allows Docker users to pass keys via `docker compose` environment
    # section without needing a local.yaml file.
    api_keys = config.setdefault("api_keys", {})
    for env_var, key_name in _ENV_KEY_MAP.items():
        value = os.getenv(env_var, "")
        if value:
            api_keys[key_name] = value

    _overlay_auth_secrets(config)
    _validate_scoring_config(config)

    return config


def _overlay_auth_secrets(config: dict[str, Any]) -> None:
    """Overlay auth secrets from the environment (never the committed config).

    Keeps OIDC/session/token secrets out of YAML files. Auth *correctness*
    (e.g. OIDC fully configured) is validated at web-app startup, not here, so
    the CLI scanner and tests that only need scanning config still load cleanly.
    """
    auth = config.setdefault("auth", {})
    oidc = auth.setdefault("oidc", {})

    session_secret = os.getenv("SOCBOX_SESSION_SECRET", "")
    if session_secret:
        auth["session_secret"] = session_secret

    client_secret = os.getenv("SOCBOX_OIDC_CLIENT_SECRET", "")
    if client_secret:
        oidc["client_secret"] = client_secret

    tokens = os.getenv("SOCBOX_API_TOKENS", "")
    if tokens:
        auth["service_tokens"] = [t.strip() for t in tokens.split(",") if t.strip()]

    # SOCBOX_AUTH_DEV=1 is the explicit, deliberate escape hatch for local testing.
    if os.getenv("SOCBOX_AUTH_DEV", "").strip().lower() in ("1", "true", "yes"):
        auth["mode"] = "dev"


def get_api_key(config: dict[str, Any], feed_name: str) -> str:
    """Retrieve an API key from config, returning empty string if missing.

    Args:
        config: The loaded configuration dictionary.
        feed_name: Name of the feed (e.g., 'virustotal').

    Returns:
        The API key string, or empty string if not configured.
    """
    return config.get("api_keys", {}).get(feed_name, "")
