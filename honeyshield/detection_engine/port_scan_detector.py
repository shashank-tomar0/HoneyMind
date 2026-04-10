"""
Port Scan Detector
==================
Detects rapid sequential port probing from a single IP.
Flags IPs that connect to multiple distinct ports within a short window.

Thresholds (configurable):
    MAX_PORTS: Maximum distinct ports before flagging (default: 5)
    TIME_WINDOW_S: Rolling window in seconds (default: 10)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_PORTS = 5
DEFAULT_TIME_WINDOW_S = 10


@dataclass
class PortProbeEvent:
    """A single port probe event."""
    ip: str
    port: int
    timestamp: float


@dataclass
class PortScanAlert:
    """Alert when port scanning is detected."""
    ip: str
    ports_probed: list[int]
    total_probes: int
    window_seconds: float
    first_probe: float
    last_probe: float
    scan_rate: float  # ports per second
    severity: str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "PORT_SCAN",
            "ip": self.ip,
            "ports_probed": sorted(self.ports_probed),
            "total_probes": self.total_probes,
            "window_seconds": self.window_seconds,
            "scan_rate_pps": round(self.scan_rate, 2),
            "severity": self.severity,
        }


class PortScanDetector:
    """
    Detects port scanning by tracking distinct ports probed per IP.

    Thread-safe for concurrent access.

    Usage::

        detector = PortScanDetector(max_ports=5, time_window_s=10)

        # Record each connection attempt
        alert = detector.record_probe("10.0.0.5", port=22)
        alert = detector.record_probe("10.0.0.5", port=80)
        alert = detector.record_probe("10.0.0.5", port=443)
        alert = detector.record_probe("10.0.0.5", port=3306)
        alert = detector.record_probe("10.0.0.5", port=5432)

        if alert:
            print(f"Port scan! {alert.total_probes} ports in {alert.window_seconds}s")
    """

    def __init__(
        self,
        max_ports: int = DEFAULT_MAX_PORTS,
        time_window_s: float = DEFAULT_TIME_WINDOW_S,
    ) -> None:
        self.max_ports = max_ports
        self.time_window_s = time_window_s

        self._probes: dict[str, list[PortProbeEvent]] = defaultdict(list)
        self._flagged_ips: set[str] = set()
        self._lock = threading.Lock()

    def record_probe(self, ip: str, port: int) -> PortScanAlert | None:
        """
        Record a port connection attempt.

        Parameters
        ----------
        ip : str
            Source IP address.
        port : int
            Destination port probed.

        Returns
        -------
        PortScanAlert or None
            Alert if port scan threshold exceeded, None otherwise.
        """
        now = time.time()
        event = PortProbeEvent(ip=ip, port=port, timestamp=now)

        with self._lock:
            self._probes[ip].append(event)
            self._prune_old_probes(ip, now)

            recent = self._probes[ip]
            distinct_ports = {e.port for e in recent}

            if len(distinct_ports) >= self.max_ports:
                self._flagged_ips.add(ip)

                elapsed = recent[-1].timestamp - recent[0].timestamp
                scan_rate = len(distinct_ports) / max(elapsed, 0.001)

                alert = PortScanAlert(
                    ip=ip,
                    ports_probed=sorted(distinct_ports),
                    total_probes=len(recent),
                    window_seconds=self.time_window_s,
                    first_probe=recent[0].timestamp,
                    last_probe=recent[-1].timestamp,
                    scan_rate=scan_rate,
                )

                logger.warning(
                    "PORT SCAN DETECTED: IP=%s ports=%s rate=%.1f/s",
                    ip, sorted(distinct_ports), scan_rate,
                )
                return alert

        return None

    def is_flagged(self, ip: str) -> bool:
        """Check if an IP is flagged for port scanning."""
        with self._lock:
            now = time.time()
            self._prune_old_probes(ip, now)
            distinct = len({e.port for e in self._probes.get(ip, [])})
            return ip in self._flagged_ips or distinct >= self.max_ports

    def get_probed_ports(self, ip: str) -> list[int]:
        """Get list of recently probed ports for an IP."""
        with self._lock:
            now = time.time()
            self._prune_old_probes(ip, now)
            return sorted({e.port for e in self._probes.get(ip, [])})

    def clear_ip(self, ip: str) -> None:
        """Clear tracking for a specific IP."""
        with self._lock:
            self._probes.pop(ip, None)
            self._flagged_ips.discard(ip)

    def reset(self) -> None:
        """Reset all tracking."""
        with self._lock:
            self._probes.clear()
            self._flagged_ips.clear()

    def stats(self) -> dict[str, Any]:
        """Current detector statistics."""
        with self._lock:
            return {
                "tracked_ips": len(self._probes),
                "flagged_ips": len(self._flagged_ips),
                "max_ports": self.max_ports,
                "time_window_s": self.time_window_s,
            }

    def _prune_old_probes(self, ip: str, now: float) -> None:
        """Remove probes outside the time window."""
        cutoff = now - self.time_window_s
        if ip in self._probes:
            self._probes[ip] = [
                e for e in self._probes[ip] if e.timestamp >= cutoff
            ]
            if not self._probes[ip]:
                del self._probes[ip]
