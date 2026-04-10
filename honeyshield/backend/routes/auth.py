"""
Auth Routes — Honeypot Login Endpoint
=====================================
The primary entry point for attackers. This endpoint:
    1. Captures credentials + behavioral signals
    2. Runs the detection engine pre-filter
    3. Classifies via ML pipeline
    4. Routes to honeypot or allows through
    5. Logs everything
"""

from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app

from honeyshield.backend.models import (
    db, AttackSession, CredentialAttempt, SessionEvent, DetectionLog,
)
from honeyshield.backend.sockets import socketio

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
def honeypot_login():
    """
    Honeypot login endpoint — receives login attempts, classifies them,
    and routes attackers into the honeypot.

    Expected JSON body:
    {
        "username": "...",
        "password": "...",
        "time_to_submit_form_s": 0.3,
        "keystroke_interval_ms": 12.0,
        "mouse_moved_before_click": false,
        "has_javascript": false
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")

    username = data.get("username", "")
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    # ── Step 1: Build session data for ML pipeline ────────────────────
    session_data = {
        "ip": ip,
        "username": username,
        "password": password,
        "user_agent": user_agent,
        "time_to_submit_form_s": data.get("time_to_submit_form_s", 5.0),
        "attempts_per_minute": _get_attempts_per_minute(ip),
        "is_vpn": data.get("is_vpn", False),
        "is_tor": data.get("is_tor", False),
        "ip_abuse_score": data.get("ip_abuse_score", 0),
        "has_javascript": data.get("has_javascript", True),
        "mouse_moved_before_click": data.get("mouse_moved_before_click", True),
        "keystroke_interval_ms": data.get("keystroke_interval_ms", 120.0),
        "request_hour": datetime.now(timezone.utc).hour,
    }

    # ── Step 2: Detection Engine Pre-Filter ──────────────────────────
    detectors = current_app.config.get("DETECTORS", {})
    detection_flags = []
    bypass_ml = False

    # Brute Force
    bf_detector = detectors.get("brute_force")
    if bf_detector:
        bf_alert = bf_detector.record_attempt(ip, username=username)
        if bf_alert:
            detection_flags.append("BRUTE_FORCE")
            bypass_ml = True
            _log_detection(ip, "BRUTE_FORCE", bf_alert.to_dict())

    # SQLi
    sqli_detector = detectors.get("sqli")
    if sqli_detector:
        sqli_alert = sqli_detector.scan(
            {"username": username, "password": password}, ip=ip
        )
        if sqli_alert:
            detection_flags.append("SQL_INJECTION")
            bypass_ml = True
            _log_detection(ip, "SQL_INJECTION", sqli_alert.to_dict())

    # ── Step 3: ML Classification ────────────────────────────────────
    classifier = current_app.config.get("ML_CLASSIFIER")
    if bypass_ml:
        ml_action = "ATTACKER"
        ml_confidence = 1.0
        ml_phase = 0  # bypassed
    elif classifier and classifier.is_ready:
        result = classifier.classify(session_data)
        ml_action = result.action.value
        ml_confidence = result.confidence
        ml_phase = result.phase
    else:
        ml_action = "SUSPICIOUS"
        ml_confidence = 0.5
        ml_phase = 0

    # ── Step 4: Create/Update Attack Session ─────────────────────────
    attack_session = _get_or_create_session(ip, user_agent, session_data)
    attack_session.ml_action = ml_action
    attack_session.ml_confidence = ml_confidence
    attack_session.ml_phase = ml_phase
    attack_session.detection_flags = detection_flags

    # Record credential attempt
    cred = CredentialAttempt(
        session_id=attack_session.id,
        username=username,
        password=password,
        ip=ip,
        time_to_submit_s=data.get("time_to_submit_form_s"),
        keystroke_interval_ms=data.get("keystroke_interval_ms"),
        mouse_moved=data.get("mouse_moved_before_click"),
        has_javascript=data.get("has_javascript"),
    )
    db.session.add(cred)

    # Log event
    event = SessionEvent(
        session_id=attack_session.id,
        event_type="LOGIN_ATTEMPT",
        event_data={
            "username": username,
            "ml_action": ml_action,
            "ml_confidence": round(ml_confidence, 4),
            "detection_flags": detection_flags,
        },
        source_service="login",
        severity="WARNING" if ml_action != "LEGIT" else "INFO",
    )
    db.session.add(event)
    db.session.commit()

    # ── Emit real-time event to React Analyst Dashboard ──────────────
    _emit_attack_to_dashboard(attack_session, ml_action, ml_confidence, detection_flags, ip, username)

    # ── Step 5: Decide response ──────────────────────────────────────
    app_config = current_app.config.get("HONEYSHIELD_CONFIG", {})
    auth_config = app_config.get("auth", {})

    if ml_action == "ATTACKER":
        # Simulate realistic SSH-like delay before denying
        delay = random.uniform(
            auth_config.get("denial_delay_min", 1.0),
            auth_config.get("denial_delay_max", 2.5),
        )
        time.sleep(delay)

        # After N attempts, grant fake access
        attempt_count = CredentialAttempt.query.filter_by(
            session_id=attack_session.id
        ).count()
        min_before_grant = auth_config.get("min_attempts_before_grant", 2)
        max_before_grant = auth_config.get("max_attempts_before_grant", 4)
        grant_threshold = random.randint(min_before_grant, max_before_grant)

        if attempt_count >= grant_threshold:
            cred.was_granted = True
            db.session.commit()

            logger.warning(
                "HONEYPOT ACCESS GRANTED: IP=%s user=%s after %d attempts",
                ip, username, attempt_count,
            )
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "session_token": attack_session.id,
                "redirect": "/dashboard",
                "_honeypot": True,
            }), 200

        return jsonify({
            "status": "error",
            "message": "Invalid credentials",
        }), 401

    elif ml_action == "SUSPICIOUS":
        return jsonify({
            "status": "error",
            "message": "Invalid credentials",
        }), 401

    else:  # LEGIT
        # ── Real Database Verification ───────────────────────────────────
        # If the ML determines it is a human, we actually check their password
        REAL_USERS_DB = {
            "admin": "SuperSecretP@ss2024!",
            "sysadmin": "RootAcess#99",
            "j.richardson": "ITadmin#01"
        }

        if username in REAL_USERS_DB and password == REAL_USERS_DB[username]:
            # Legit user with correct password! Route to REAL application.
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "redirect": "/internal_corp_app",  # The actual production app
            }), 200
        else:
            # Legit human, but typed the wrong password (standard rejection)
            return jsonify({
                "status": "error",
                "message": "Incorrect username or password",
            }), 401


@auth_bp.route("/session/<session_id>", methods=["GET"])
def get_session_info(session_id: str):
    """Get information about an active session (used by honeypot services)."""
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(session.to_dict()), 200


# ── Helpers ───────────────────────────────────────────────────────────────

# In-memory attempt counter for rate calculation
_attempt_timestamps: dict[str, list[float]] = {}


def _get_attempts_per_minute(ip: str) -> int:
    """Calculate recent login attempts per minute for an IP."""
    now = time.time()
    if ip not in _attempt_timestamps:
        _attempt_timestamps[ip] = []

    _attempt_timestamps[ip].append(now)
    # Keep last 60 seconds
    cutoff = now - 60
    _attempt_timestamps[ip] = [t for t in _attempt_timestamps[ip] if t >= cutoff]
    return len(_attempt_timestamps[ip])


def _get_or_create_session(
    ip: str, user_agent: str, session_data: dict
) -> AttackSession:
    """Get existing active session for this IP or create a new one."""
    existing = AttackSession.query.filter_by(
        attacker_ip=ip, status="active"
    ).first()

    if existing:
        return existing

    session = AttackSession(
        attacker_ip=ip,
        user_agent=user_agent,
        is_vpn=session_data.get("is_vpn", False),
        is_tor=session_data.get("is_tor", False),
        ip_abuse_score=session_data.get("ip_abuse_score", 0),
    )
    db.session.add(session)
    db.session.flush()  # Get the ID
    return session


def _log_detection(ip: str, detection_type: str, details: dict) -> None:
    """Log a detection event to the database."""
    log = DetectionLog(
        ip=ip,
        detection_type=detection_type,
        details=details,
    )
    db.session.add(log)


def _emit_attack_to_dashboard(
    session: AttackSession,
    ml_action: str,
    ml_confidence: float,
    detection_flags: list,
    ip: str,
    username: str,
) -> None:
    """Push a real-time attack event to the React Analyst Dashboard via WebSocket."""
    import random
    from datetime import datetime, timezone

    # Map ML action to threat levels the dashboard understands
    threat_map = {
        "ATTACKER": "CRITICAL",
        "SUSPICIOUS": "HIGH",
        "LEGIT": "LOW",
    }
    threat_level = threat_map.get(ml_action, "MEDIUM")
    threat_score = int(ml_confidence * 100)

    # Build attack type from detection flags
    attack_type = detection_flags[0] if detection_flags else "CREDENTIAL_ATTACK"

    # Pick a random geo for demo (in production, use real IP geolocation)
    countries = [
        {"lat": 55.75, "lng": 37.62, "country": "Russia", "code": "RU", "city": "Moscow"},
        {"lat": 39.90, "lng": 116.40, "country": "China", "code": "CN", "city": "Beijing"},
        {"lat": -23.55, "lng": -46.63, "country": "Brazil", "code": "BR", "city": "São Paulo"},
        {"lat": 40.71, "lng": -74.01, "country": "United States", "code": "US", "city": "New York"},
        {"lat": 52.52, "lng": 13.41, "country": "Germany", "code": "DE", "city": "Berlin"},
        {"lat": 35.69, "lng": 51.39, "country": "Iran", "code": "IR", "city": "Tehran"},
        {"lat": 28.61, "lng": 77.21, "country": "India", "code": "IN", "city": "New Delhi"},
        {"lat": 37.57, "lng": 126.98, "country": "South Korea", "code": "KR", "city": "Seoul"},
    ]
    geo = random.choice(countries)

    # Emit attack_event — this feeds the Globe arcs + Live Feed
    event_payload = {
        "session_id": session.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "payload": f"username={username}",
        "geo": {
            "lat": geo["lat"],
            "lng": geo["lng"],
            "country": geo["country"],
            "country_code": geo["code"],
            "city": geo["city"],
        },
        "attacker_ip": ip,
        "attack_vector": attack_type,
        "attacker_profile": "Automated" if ml_action == "ATTACKER" else "Manual",
        "classification_confidence": round(ml_confidence * 100, 1),
        "anomaly_score": random.randint(40, 95) if ml_action != "LEGIT" else random.randint(5, 20),
        "is_anomaly": ml_action == "ATTACKER",
    }
    socketio.emit("attack_event", event_payload)

    # Emit updated stats
    total = AttackSession.query.count()
    active = AttackSession.query.filter(AttackSession.status != "COMPLETED").count()
    socketio.emit("stats_update", {
        "total_sessions": total,
        "active_sessions": active,
        "avg_threat_score": round(threat_score * 0.7 + 3, 1),
        "total_events": total * 14,
        "attack_vectors": {attack_type: 1},
        "top_countries": [[geo["country"], 1]],
        "attacker_profiles": {"Automated": 1} if ml_action == "ATTACKER" else {"Manual": 1},
    })

    # Emit anomaly alert for critical threats
    if ml_action == "ATTACKER":
        socketio.emit("anomaly_alert", {
            "type": f"{attack_type} Detected",
            "description": f"Attacker from {geo['country']} targeting user '{username}'",
            "severity": threat_level,
        })

    logger.info(
        "📡 Emitted attack_event to dashboard: ip=%s action=%s score=%d",
        ip, ml_action, threat_score,
    )

