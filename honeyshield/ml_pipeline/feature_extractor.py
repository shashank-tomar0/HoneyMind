"""
Feature Extractor
=================
Converts a raw session dictionary into a 12-dimensional numpy feature
vector used by the ML classifier.

Feature Vector (12 signals):
    0  time_to_submit_form_s   - Bots < 1s, humans 3–8s
    1  attempts_per_minute     - High = brute force
    2  is_vpn                  - VPN detected (bool → int)
    3  is_tor                  - TOR exit node (bool → int)
    4  ip_abuse_score          - AbuseIPDB score 0–100
    5  username_is_common      - admin, root, test, guest, ubuntu
    6  password_in_wordlist    - Match in top-10k rockyou.txt
    7  user_agent_is_headless  - Headless Chrome = bot
    8  has_javascript          - Bots often skip JS execution
    9  mouse_moved_before_click - Human behavioral signal
    10 keystroke_interval_ms   - Bots are too fast/uniform
    11 request_hour            - 2–5 AM = elevated risk
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

FEATURE_NAMES: list[str] = [
    "time_to_submit_form_s",
    "attempts_per_minute",
    "is_vpn",
    "is_tor",
    "ip_abuse_score",
    "username_is_common",
    "password_in_wordlist",
    "user_agent_is_headless",
    "has_javascript",
    "mouse_moved_before_click",
    "keystroke_interval_ms",
    "request_hour",
]

NUM_FEATURES: int = len(FEATURE_NAMES)

# Commonly targeted default usernames
COMMON_USERNAMES: set[str] = {
    "admin", "root", "test", "guest", "ubuntu", "user",
    "administrator", "oracle", "postgres", "mysql", "ftp",
    "www", "www-data", "pi", "vagrant", "deploy", "ec2-user",
    "centos", "jenkins", "git", "nagios", "support", "info",
}

# Headless / bot user-agent indicators
HEADLESS_INDICATORS: list[str] = [
    "headlesschrome",
    "phantomjs",
    "selenium",
    "puppeteer",
    "playwright",
    "httpclient",
    "python-requests",
    "go-http-client",
    "curl/",
    "wget/",
    "scrapy",
    "bot",
    "crawler",
    "spider",
]

# ── Wordlist Loader ───────────────────────────────────────────────────────

_WORDLIST_DIR = Path(__file__).parent / "wordlists"
_PASSWORD_WORDLIST: set[str] | None = None


def _load_password_wordlist() -> set[str]:
    """Lazily load the top-10k password wordlist into memory."""
    global _PASSWORD_WORDLIST
    if _PASSWORD_WORDLIST is not None:
        return _PASSWORD_WORDLIST

    wordlist_path = _WORDLIST_DIR / "top10k_passwords.txt"
    if not wordlist_path.exists():
        logger.warning(
            "Password wordlist not found at %s — password_in_wordlist "
            "feature will always be 0.",
            wordlist_path,
        )
        _PASSWORD_WORDLIST = set()
        return _PASSWORD_WORDLIST

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        _PASSWORD_WORDLIST = {line.strip().lower() for line in fh if line.strip()}

    logger.info("Loaded %d passwords from wordlist.", len(_PASSWORD_WORDLIST))
    return _PASSWORD_WORDLIST


# ── Feature Extractor ─────────────────────────────────────────────────────


class FeatureExtractor:
    """
    Transforms a raw login-session dictionary into the 12-dim feature
    vector expected by the ML classifier.

    Usage::

        extractor = FeatureExtractor()
        features = extractor.extract(session_dict)
        # features.shape == (12,)
    """

    def __init__(self) -> None:
        self._password_wordlist: set[str] = _load_password_wordlist()

    # ── Public API ────────────────────────────────────────────────────

    def extract(self, session: dict[str, Any]) -> np.ndarray:
        """
        Extract the 12-dimensional feature vector from a raw session dict.

        Parameters
        ----------
        session : dict
            Raw login session data. Expected keys documented below — any
            missing key gracefully falls back to a safe default.

        Returns
        -------
        numpy.ndarray
            Shape ``(12,)`` float64 feature vector.
        """
        features = np.zeros(NUM_FEATURES, dtype=np.float64)

        # 0 — time_to_submit_form_s
        features[0] = float(session.get("time_to_submit_form_s", 5.0))

        # 1 — attempts_per_minute
        features[1] = float(session.get("attempts_per_minute", 0))

        # 2 — is_vpn
        features[2] = float(bool(session.get("is_vpn", False)))

        # 3 — is_tor
        features[3] = float(bool(session.get("is_tor", False)))

        # 4 — ip_abuse_score (0–100)
        abuse_score = session.get("ip_abuse_score", 0)
        features[4] = float(max(0, min(100, abuse_score)))

        # 5 — username_is_common
        username = str(session.get("username", "")).strip().lower()
        features[5] = float(username in COMMON_USERNAMES)

        # 6 — password_in_wordlist
        password = str(session.get("password", "")).strip().lower()
        features[6] = float(password in self._password_wordlist) if password else 0.0

        # 7 — user_agent_is_headless
        ua = str(session.get("user_agent", "")).lower()
        features[7] = float(any(ind in ua for ind in HEADLESS_INDICATORS))

        # 8 — has_javascript
        features[8] = float(bool(session.get("has_javascript", True)))

        # 9 — mouse_moved_before_click
        features[9] = float(bool(session.get("mouse_moved_before_click", True)))

        # 10 — keystroke_interval_ms
        features[10] = float(session.get("keystroke_interval_ms", 120.0))

        # 11 — request_hour (0–23)
        features[11] = float(session.get("request_hour", 12))

        return features

    def extract_batch(
        self, sessions: list[dict[str, Any]]
    ) -> np.ndarray:
        """
        Extract features for multiple sessions at once.

        Returns
        -------
        numpy.ndarray
            Shape ``(n_sessions, 12)`` float64 matrix.
        """
        return np.vstack([self.extract(s) for s in sessions])

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def feature_names() -> list[str]:
        """Return ordered list of feature names."""
        return list(FEATURE_NAMES)
