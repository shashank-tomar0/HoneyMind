"""
SQL Injection Detector
======================
Regex + pattern matching engine that scans form fields for SQL injection
payloads. Catches common SQLi patterns including:
    - Union-based injection
    - Boolean-based blind injection
    - Time-based blind injection
    - Error-based injection
    - Stacked queries
    - Comment-based evasion
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── SQLi Patterns ─────────────────────────────────────────────────────────

SQLI_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # (name, severity, compiled_regex)
    ("union_select", "HIGH", re.compile(
        r"(?:union\s+(?:all\s+)?select)", re.IGNORECASE
    )),
    ("or_true", "MEDIUM", re.compile(
        r"(?:'\s*or\s+'?\d+'?\s*=\s*'?\d+'?)", re.IGNORECASE
    )),
    ("or_1eq1", "MEDIUM", re.compile(
        r"(?:'\s*or\s+1\s*=\s*1)", re.IGNORECASE
    )),
    ("and_true", "MEDIUM", re.compile(
        r"(?:'\s*and\s+'?\d+'?\s*=\s*'?\d+'?)", re.IGNORECASE
    )),
    ("comment_evasion", "MEDIUM", re.compile(
        r"(?:--\s*$|/\*.*?\*/|#\s*$)", re.IGNORECASE
    )),
    ("sleep_injection", "HIGH", re.compile(
        r"(?:sleep\s*\(\s*\d+\s*\))", re.IGNORECASE
    )),
    ("benchmark_injection", "HIGH", re.compile(
        r"(?:benchmark\s*\(\s*\d+)", re.IGNORECASE
    )),
    ("waitfor_delay", "HIGH", re.compile(
        r"(?:waitfor\s+delay\s+')", re.IGNORECASE
    )),
    ("drop_table", "CRITICAL", re.compile(
        r"(?:drop\s+table)", re.IGNORECASE
    )),
    ("insert_into", "HIGH", re.compile(
        r"(?:insert\s+into)", re.IGNORECASE
    )),
    ("update_set", "HIGH", re.compile(
        r"(?:update\s+\w+\s+set)", re.IGNORECASE
    )),
    ("delete_from", "CRITICAL", re.compile(
        r"(?:delete\s+from)", re.IGNORECASE
    )),
    ("exec_xp", "CRITICAL", re.compile(
        r"(?:exec\s+(?:xp_|sp_))", re.IGNORECASE
    )),
    ("information_schema", "HIGH", re.compile(
        r"(?:information_schema)", re.IGNORECASE
    )),
    ("load_file", "CRITICAL", re.compile(
        r"(?:load_file\s*\()", re.IGNORECASE
    )),
    ("into_outfile", "CRITICAL", re.compile(
        r"(?:into\s+(?:out|dump)file)", re.IGNORECASE
    )),
    ("hex_encoding", "MEDIUM", re.compile(
        r"(?:0x[0-9a-fA-F]+)", re.IGNORECASE
    )),
    ("char_function", "MEDIUM", re.compile(
        r"(?:char\s*\(\s*\d+)", re.IGNORECASE
    )),
    ("concat_function", "LOW", re.compile(
        r"(?:concat\s*\()", re.IGNORECASE
    )),
    ("single_quote_escape", "LOW", re.compile(
        r"(?:'{2,}|\\'){1,}", re.IGNORECASE
    )),
    ("stacked_queries", "HIGH", re.compile(
        r"(?:;\s*(?:select|insert|update|delete|drop|exec))", re.IGNORECASE
    )),
]

# ── Data Classes ──────────────────────────────────────────────────────────


@dataclass
class SQLiMatch:
    """A single SQLi pattern match."""
    pattern_name: str
    severity: str
    matched_text: str
    field_name: str
    field_value: str


@dataclass
class SQLiAlert:
    """Alert when SQLi is detected in form input."""
    ip: str
    matches: list[SQLiMatch]
    max_severity: str
    total_patterns_matched: int
    payload_fields: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "SQL_INJECTION",
            "ip": self.ip,
            "max_severity": self.max_severity,
            "total_patterns_matched": self.total_patterns_matched,
            "matches": [
                {
                    "pattern": m.pattern_name,
                    "severity": m.severity,
                    "matched_text": m.matched_text,
                    "field": m.field_name,
                }
                for m in self.matches
            ],
            "payload_fields": self.payload_fields,
        }


# ── Severity Ranking ──────────────────────────────────────────────────────

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── Detector ──────────────────────────────────────────────────────────────


class SQLiDetector:
    """
    Scans form field values for SQL injection patterns.

    Usage::

        detector = SQLiDetector()

        form_data = {
            "username": "admin' OR '1'='1",
            "password": "'; DROP TABLE users; --"
        }

        alert = detector.scan(form_data, ip="10.0.0.1")
        if alert:
            print(f"SQLi detected! Severity: {alert.max_severity}")
            for match in alert.matches:
                print(f"  {match.pattern_name} in '{match.field_name}'")
    """

    def __init__(self, custom_patterns: list[tuple[str, str, str]] | None = None):
        """
        Initialize the detector.

        Parameters
        ----------
        custom_patterns : list of (name, severity, regex_str), optional
            Additional custom patterns to check alongside the defaults.
        """
        self._patterns = list(SQLI_PATTERNS)

        if custom_patterns:
            for name, severity, regex_str in custom_patterns:
                self._patterns.append(
                    (name, severity, re.compile(regex_str, re.IGNORECASE))
                )

    def scan(
        self,
        form_data: dict[str, str],
        ip: str = "unknown",
    ) -> SQLiAlert | None:
        """
        Scan all form fields for SQL injection patterns.

        Parameters
        ----------
        form_data : dict
            Form field names and values. All values are scanned.
        ip : str
            Source IP for the alert.

        Returns
        -------
        SQLiAlert or None
            Alert with all matches if SQLi detected, None otherwise.
        """
        all_matches: list[SQLiMatch] = []

        for field_name, field_value in form_data.items():
            if not isinstance(field_value, str) or not field_value.strip():
                continue

            for pattern_name, severity, regex in self._patterns:
                match = regex.search(field_value)
                if match:
                    all_matches.append(SQLiMatch(
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_text=match.group(0),
                        field_name=field_name,
                        field_value=field_value,
                    ))

        if not all_matches:
            return None

        # Determine max severity
        max_sev = max(
            all_matches, key=lambda m: SEVERITY_RANK.get(m.severity, 0)
        ).severity

        alert = SQLiAlert(
            ip=ip,
            matches=all_matches,
            max_severity=max_sev,
            total_patterns_matched=len(all_matches),
            payload_fields={m.field_name: m.field_value for m in all_matches},
        )

        logger.warning(
            "SQL INJECTION DETECTED: IP=%s severity=%s patterns=%d fields=%s",
            ip, max_sev, len(all_matches),
            list(alert.payload_fields.keys()),
        )
        return alert

    def is_sqli(self, value: str) -> bool:
        """Quick check if a single string contains SQLi patterns."""
        for _, _, regex in self._patterns:
            if regex.search(value):
                return True
        return False

    def scan_single_field(
        self, field_name: str, field_value: str
    ) -> list[SQLiMatch]:
        """Scan a single field value and return all matches."""
        matches = []
        for pattern_name, severity, regex in self._patterns:
            match = regex.search(field_value)
            if match:
                matches.append(SQLiMatch(
                    pattern_name=pattern_name,
                    severity=severity,
                    matched_text=match.group(0),
                    field_name=field_name,
                    field_value=field_value,
                ))
        return matches
