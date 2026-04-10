"""
Brute Force Detector
====================
Tracks failed login attempts per IP within a rolling time window.
If an IP exceeds the threshold, it is immediately flagged — bypassing
the ML pipeline and routing straight to the honeypot.

Configurable:
    MAX_ATTEMPTS: Number of failed attempts before flagging (default: 5)
    TIME_WINDOW_S: Rolling window in seconds (default: 60)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Default Thresholds ────────────────────────────────────────────────────

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_TIME_WINDOW_S = 60


@dataclass
class BruteForceEvent:
    """A single failed login attempt event."""
    ip: str
    timestamp: float
    username: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BruteForceAlert:
    """Alert generated when brute force threshold is exceeded."""
    ip: str
    attempts: int
    window_seconds: float
    usernames_tried: list[str]
    first_attempt: float
    last_attempt: float
    severity: str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "BRUTE_FORCE",
            "ip": self.ip,
            "attempts": self.attempts,
            "window_seconds": self.window_seconds,
            "usernames_tried": self.usernames_tried,
            "first_attempt": self.first_attempt,
            "last_attempt": self.last_attempt,
            "severity": self.severity,
        }


class BruteForceDetector:
    """
    Detects brute force login attempts by tracking failed logins per IP.

    Thread-safe — uses a lock for concurrent access from multiple
    request handlers.

    Usage::

        detector = BruteForceDetector(max_attempts=5, time_window_s=60)

        # Record a failed login
        alert = detector.record_attempt("192.168.1.100", username="admin")

        if alert:
            # Threshold exceeded — route to honeypot
            print(f"Brute force detected: {alert.attempts} attempts")

        # Check without recording
        if detector.is_flagged("192.168.1.100"):
            print("IP is flagged")
    """

    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        time_window_s: float = DEFAULT_TIME_WINDOW_S,
    ) -> None:
        self.max_attempts = max_attempts
        self.time_window_s = time_window_s

        # {ip: [BruteForceEvent, ...]}
        self._attempts: dict[str, list[BruteForceEvent]] = defaultdict(list)
        self._flagged_ips: set[str] = set()
        self._lock = threading.Lock()

    def record_attempt(
        self,
        ip: str,
        username: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> BruteForceAlert | None:
        """
        Record a failed login attempt and check if threshold is exceeded.

        Parameters
        ----------
        ip : str
            Source IP address.
        username : str
            Username attempted.
        metadata : dict, optional
            Additional context (user_agent, etc.).

        Returns
        -------
        BruteForceAlert or None
            Alert if threshold exceeded, None otherwise.
        """
        now = time.time()

        event = BruteForceEvent(
            ip=ip,
            timestamp=now,
            username=username,
            metadata=metadata or {},
        )

        with self._lock:
            self._attempts[ip].append(event)
            self._prune_old_attempts(ip, now)

            recent = self._attempts[ip]

            if len(recent) >= self.max_attempts:
                self._flagged_ips.add(ip)
                usernames = list({e.username for e in recent if e.username})

                alert = BruteForceAlert(
                    ip=ip,
                    attempts=len(recent),
                    window_seconds=self.time_window_s,
                    usernames_tried=usernames,
                    first_attempt=recent[0].timestamp,
                    last_attempt=recent[-1].timestamp,
                )

                logger.warning(
                    "BRUTE FORCE DETECTED: IP=%s attempts=%d usernames=%s",
                    ip, len(recent), usernames,
                )
                return alert

        return None

    def is_flagged(self, ip: str) -> bool:
        """Check if an IP is currently flagged for brute force."""
        with self._lock:
            # Also check if active attempts exceed threshold
            now = time.time()
            self._prune_old_attempts(ip, now)
            recent_count = len(self._attempts.get(ip, []))
            return ip in self._flagged_ips or recent_count >= self.max_attempts

    def get_attempt_count(self, ip: str) -> int:
        """Get the current number of recent attempts for an IP."""
        with self._lock:
            now = time.time()
            self._prune_old_attempts(ip, now)
            return len(self._attempts.get(ip, []))

    def clear_ip(self, ip: str) -> None:
        """Clear tracking data for a specific IP."""
        with self._lock:
            self._attempts.pop(ip, None)
            self._flagged_ips.discard(ip)

    def reset(self) -> None:
        """Reset all tracking data."""
        with self._lock:
            self._attempts.clear()
            self._flagged_ips.clear()

    def get_flagged_ips(self) -> list[str]:
        """Return all currently flagged IPs."""
        with self._lock:
            return list(self._flagged_ips)

    def stats(self) -> dict[str, Any]:
        """Return current detector statistics."""
        with self._lock:
            return {
                "tracked_ips": len(self._attempts),
                "flagged_ips": len(self._flagged_ips),
                "max_attempts": self.max_attempts,
                "time_window_s": self.time_window_s,
            }

    def _prune_old_attempts(self, ip: str, now: float) -> None:
        """Remove attempts outside the rolling time window."""
        cutoff = now - self.time_window_s
        if ip in self._attempts:
            self._attempts[ip] = [
                e for e in self._attempts[ip] if e.timestamp >= cutoff
            ]
            if not self._attempts[ip]:
                del self._attempts[ip]
