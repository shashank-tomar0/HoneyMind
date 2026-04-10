"""
Intelligence Routes
===================
API endpoints for the intelligence layer:
    - IP enrichment (geolocation, ISP, VPN detection)
    - Behavioral risk scoring
    - Threat report generation
"""

from __future__ import annotations

import logging
import time

import requests as http_requests
from flask import Blueprint, request, jsonify

from honeyshield.backend.models import (
    db, AttackSession, CredentialAttempt, ShellCommand, CanaryHit,
)

logger = logging.getLogger(__name__)

intelligence_bp = Blueprint("intelligence", __name__, url_prefix="/api/intelligence")

# ── IP Enrichment Cache ──────────────────────────────────────────────────

_ip_cache: dict[str, dict] = {}
_ip_cache_ttl: dict[str, float] = {}
CACHE_TTL_S = 24 * 3600  # 24 hours


# ── IP Enrichment ────────────────────────────────────────────────────────


@intelligence_bp.route("/enrich/<ip>", methods=["GET"])
def enrich_ip(ip: str):
    """
    Enrich an IP address with geolocation, ISP, and VPN information.
    Uses ipapi.co free tier (no API key needed).
    """
    # Check cache
    now = time.time()
    if ip in _ip_cache and (now - _ip_cache_ttl.get(ip, 0)) < CACHE_TTL_S:
        return jsonify({"ip": ip, "data": _ip_cache[ip], "cached": True}), 200

    try:
        resp = http_requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5,
            headers={"User-Agent": "HoneyShield/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            enriched = {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "isp": data.get("org"),
                "asn": data.get("asn"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone"),
                "is_vpn": _detect_vpn(data),
            }

            # Cache the result
            _ip_cache[ip] = enriched
            _ip_cache_ttl[ip] = now

            return jsonify({"ip": ip, "data": enriched, "cached": False}), 200
        else:
            return jsonify({"error": f"IP lookup failed: {resp.status_code}"}), 502

    except http_requests.RequestException as e:
        logger.warning("IP enrichment failed for %s: %s", ip, e)
        return jsonify({"error": f"IP enrichment failed: {str(e)}"}), 502


@intelligence_bp.route("/enrich/session/<session_id>", methods=["POST"])
def enrich_session(session_id: str):
    """Enrich a session's IP and update the database."""
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    ip = session.attacker_ip

    # Fetch enrichment
    try:
        resp = http_requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5,
            headers={"User-Agent": "HoneyShield/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            session.geo_city = data.get("city")
            session.geo_region = data.get("region")
            session.geo_country = data.get("country_name")
            session.geo_isp = data.get("org")
            session.is_vpn = _detect_vpn(data)
            db.session.commit()

            return jsonify({
                "status": "enriched",
                "session_id": session_id,
                "geo": {
                    "city": session.geo_city,
                    "country": session.geo_country,
                    "isp": session.geo_isp,
                },
            }), 200
    except http_requests.RequestException as e:
        return jsonify({"error": str(e)}), 502

    return jsonify({"error": "Enrichment failed"}), 500


# ── Behavioral Risk Scoring ──────────────────────────────────────────────


@intelligence_bp.route("/risk-score/<session_id>", methods=["GET"])
def calculate_risk_score(session_id: str):
    """
    Calculate behavioral risk score (1-10) for a session.

    Scoring signals:
        > 10 credential attempts          +2
        Common username used               +1
        Wordlist password used             +1
        /etc/passwd accessed               +1
        File download attempted            +2
        Canary token triggered             +2
        Pivoting attempt detected          +3
        Privilege escalation attempt       +3
    """
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    score = 0
    signals = []

    # Credential attempts
    cred_count = session.credentials.count()
    if cred_count > 10:
        score += 2
        signals.append({"signal": "excessive_credentials", "count": cred_count, "points": 2})

    # Common usernames
    from honeyshield.ml_pipeline.feature_extractor import COMMON_USERNAMES
    creds = session.credentials.all()
    common_used = any(c.username.lower() in COMMON_USERNAMES for c in creds)
    if common_used:
        score += 1
        signals.append({"signal": "common_username", "points": 1})

    # Wordlist passwords
    from honeyshield.ml_pipeline.feature_extractor import _load_password_wordlist
    wordlist = _load_password_wordlist()
    wordlist_used = any(c.password.lower() in wordlist for c in creds if c.password)
    if wordlist_used:
        score += 1
        signals.append({"signal": "wordlist_password", "points": 1})

    # Shell commands analysis
    commands = session.shell_commands.all()
    for cmd in commands:
        if cmd.flag_raised == "PRIVILEGE_ESCALATION":
            score += 3
            signals.append({"signal": "privilege_escalation", "command": cmd.command, "points": 3})
        elif cmd.flag_raised == "PIVOTING_ATTEMPT":
            score += 3
            signals.append({"signal": "pivoting_attempt", "command": cmd.command, "points": 3})
        elif cmd.flag_raised == "ATTEMPTED_DOWNLOAD":
            score += 2
            signals.append({"signal": "file_download", "command": cmd.command, "points": 2})
        elif cmd.flag_raised == "ATTEMPTED_EXECUTION":
            score += 2
            signals.append({"signal": "execution_attempt", "command": cmd.command, "points": 2})

    # Check /etc/passwd access
    passwd_access = any("passwd" in (c.command or "") for c in commands)
    if passwd_access:
        score += 1
        signals.append({"signal": "passwd_access", "points": 1})

    # Canary token triggered
    canary_count = session.canary_hits.count()
    if canary_count > 0:
        score += 2
        signals.append({"signal": "canary_triggered", "count": canary_count, "points": 2})

    # Clamp to 1-10
    score = max(1, min(10, score))

    # Update session
    session.risk_score = score
    db.session.commit()

    return jsonify({
        "session_id": session_id,
        "risk_score": score,
        "signals": signals,
        "signal_count": len(signals),
    }), 200


# ── Threat Report ────────────────────────────────────────────────────────


@intelligence_bp.route("/report/<session_id>", methods=["GET"])
def generate_threat_report(session_id: str):
    """Generate a structured threat intelligence report for a session."""
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    credentials = [c.to_dict() for c in session.credentials.order_by(
        CredentialAttempt.timestamp
    ).all()]

    commands = [c.to_dict() for c in session.shell_commands.order_by(
        ShellCommand.timestamp
    ).all()]

    canary_hits = [h.to_dict() for h in session.canary_hits.all()]

    flags_raised = list({
        c["flag_raised"] for c in commands if c.get("flag_raised")
    })

    report = {
        "session_id": session.id,
        "timestamp": session.created_at.isoformat() if session.created_at else None,
        "duration_seconds": session.duration_seconds,
        "status": session.status,

        "attacker_ip": session.attacker_ip,
        "real_ip_via_canary": session.real_ip_via_canary,
        "geolocation": {
            "city": session.geo_city,
            "region": session.geo_region,
            "country": session.geo_country,
            "isp": session.geo_isp,
        },
        "is_vpn": session.is_vpn,
        "is_tor": session.is_tor,

        "services_probed": session.services_probed or [],
        "credentials_tried": credentials,
        "total_credential_attempts": len(credentials),

        "shell_commands": commands,
        "total_commands": len(commands),
        "flags_raised": flags_raised,

        "canary_hits": canary_hits,

        "risk_score": session.risk_score,
        "ml_confidence": session.ml_confidence,
        "ml_phase": session.ml_phase,
        "ml_action": session.ml_action,

        "detection_flags": session.detection_flags or [],

        "recommended_actions": _generate_recommendations(session, flags_raised),
    }

    return jsonify(report), 200


# ── Helpers ───────────────────────────────────────────────────────────────


def _detect_vpn(geo_data: dict) -> bool:
    """Heuristic VPN detection based on ISP/org name."""
    org = (geo_data.get("org") or "").lower()
    vpn_keywords = [
        "vpn", "proxy", "hosting", "datacenter", "data center",
        "cloud", "digitalocean", "linode", "vultr", "aws", "azure",
        "google cloud", "hetzner", "ovh", "contabo",
    ]
    return any(kw in org for kw in vpn_keywords)


def _generate_recommendations(session, flags: list[str]) -> list[str]:
    """Generate defensive action recommendations based on session analysis."""
    recs = []

    if session.risk_score >= 8:
        recs.append("CRITICAL: Block IP at firewall level immediately")
        recs.append("Submit IP to threat intelligence sharing platforms")

    if "PIVOTING_ATTEMPT" in flags:
        recs.append("Audit all systems reachable from the probed network segment")
        recs.append("Check for lateral movement indicators on target IPs")

    if "PRIVILEGE_ESCALATION" in flags:
        recs.append("Review sudo/privilege configurations on production systems")

    if "ATTEMPTED_DOWNLOAD" in flags:
        recs.append("Scan network for IOCs from the attempted download URLs")

    if session.real_ip_via_canary and session.real_ip_via_canary != session.attacker_ip:
        recs.append(
            f"Attacker's real IP ({session.real_ip_via_canary}) differs from "
            f"attack IP ({session.attacker_ip}) — VPN/proxy bypass confirmed"
        )

    if not recs:
        recs.append("Monitor — no immediate action required")

    return recs
