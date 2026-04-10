"""
HoneyShield Flask Backend — Configuration
==========================================
Loads configuration from config.yaml and environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# ── Paths ──────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent.parent  # honeyshield project root
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """
    Load configuration from YAML file with environment variable overrides.

    Parameters
    ----------
    config_path : str or Path, optional
        Path to config.yaml. Defaults to project root.

    Returns
    -------
    dict
        Merged configuration dictionary.
    """
    path = Path(config_path) if config_path else CONFIG_PATH

    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    # Apply defaults
    return _apply_defaults(config)


def _apply_defaults(config: dict[str, Any]) -> dict[str, Any]:
    """Apply default values for any missing configuration keys."""

    defaults = {
        "detection": {
            "brute_force_max_attempts": 5,
            "brute_force_window_seconds": 60,
            "port_scan_max_ports": 5,
            "port_scan_window_seconds": 10,
        },
        "ml_pipeline": {
            "phase2_min_samples": 500,
            "confidence_attacker_threshold": 0.75,
            "confidence_suspicious_threshold": 0.45,
            "retrain_schedule": "monday 02:00",
        },
        "services": {
            "ssh_port": 2222,
            "ftp_port": 2121,
            "admin_panel_port": 8080,
            "backend_port": 5000,
        },
        "auth": {
            "min_attempts_before_grant": 2,
            "max_attempts_before_grant": 4,
            "denial_delay_min": 1.0,
            "denial_delay_max": 2.5,
        },
        "canary": {
            "server_url": os.getenv("CANARY_SERVER_URL", "http://localhost:5000"),
            "bait_file_types": ["html", "xlsx", "pdf"],
        },
        "intelligence": {
            "geoip_provider": "ipapi.co",
            "abuseipdb_cache_ttl_hours": 24,
        },
        "alerts": {
            "webhook_url": os.getenv("ALERT_WEBHOOK_URL", ""),
            "min_risk_score_to_alert": 7,
        },
        "database": {
            "url": os.getenv(
                "DATABASE_URL",
                "sqlite:///honeyshield.db",
            ),
        },
        "redis": {
            "url": os.getenv("REDIS_URL", "redis://localhost:6379"),
        },
        "flask": {
            "secret_key": os.getenv("FLASK_SECRET_KEY", "honeyshield-dev-secret-change-me"),
            "debug": os.getenv("FLASK_DEBUG", "true").lower() == "true",
            "host": "0.0.0.0",
            "port": 5000,
        },
    }

    # Deep merge: defaults ← config (config overrides defaults)
    return _deep_merge(defaults, config)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ── Flask Config Class ────────────────────────────────────────────────────


class FlaskConfig:
    """Flask configuration class derived from config.yaml."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or load_config()

        # Flask core
        self.SECRET_KEY = self._config["flask"]["secret_key"]
        self.DEBUG = self._config["flask"]["debug"]

        # Database
        self.SQLALCHEMY_DATABASE_URI = self._config["database"]["url"]
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": True,
        }

    @property
    def raw(self) -> dict[str, Any]:
        """Access the raw config dict."""
        return self._config
