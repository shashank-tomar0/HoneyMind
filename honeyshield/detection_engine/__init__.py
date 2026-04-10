"""
Detection Engine
================
Rule-based pre-filter that runs BEFORE the ML pipeline.

If an IP is flagged by any detector, it bypasses ML classification
and is routed directly to the honeypot.

Detectors:
    - BruteForceDetector: Tracks failed attempts per IP per time window
    - SQLiDetector: Regex + pattern match for SQLi payloads in form fields
    - PortScanDetector: Detects rapid sequential port probing
"""

from .brute_force_detector import BruteForceDetector
from .sqli_detector import SQLiDetector
from .port_scan_detector import PortScanDetector

__all__ = [
    "BruteForceDetector",
    "SQLiDetector",
    "PortScanDetector",
]
