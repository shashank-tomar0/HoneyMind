"""
Dashboard & Sessions Routes
============================
API endpoints for the admin dashboard:
    - Live attack statistics
    - Session listing and details
    - Session timeline / replay
    - Detection logs
    - Geo-distribution data
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from sqlalchemy import func, desc

from honeyshield.backend.models import (
    db, AttackSession, CredentialAttempt, ShellCommand,
    CanaryHit, SessionEvent, DetectionLog,
)

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


# ── Dashboard Stats ──────────────────────────────────────────────────────


@dashboard_bp.route("/stats", methods=["GET"])
def dashboard_stats():
    """
    Get aggregate dashboard statistics.
    Query params: ?hours=24 (default: look back 24 hours)
    """
    hours = request.args.get("hours", 24, type=int)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    total_sessions = AttackSession.query.filter(
        AttackSession.created_at >= since
    ).count()

    active_sessions = AttackSession.query.filter_by(status="active").count()

    attacker_count = AttackSession.query.filter(
        AttackSession.created_at >= since,
        AttackSession.ml_action == "ATTACKER",
    ).count()

    suspicious_count = AttackSession.query.filter(
        AttackSession.created_at >= since,
        AttackSession.ml_action == "SUSPICIOUS",
    ).count()

    total_credentials = CredentialAttempt.query.filter(
        CredentialAttempt.timestamp >= since
    ).count()

    total_canary_hits = CanaryHit.query.filter(
        CanaryHit.timestamp >= since
    ).count()

    total_detections = DetectionLog.query.filter(
        DetectionLog.timestamp >= since
    ).count()

    # Average risk score
    avg_risk = db.session.query(
        func.avg(AttackSession.risk_score)
    ).filter(
        AttackSession.created_at >= since,
        AttackSession.risk_score > 0,
    ).scalar() or 0

    return jsonify({
        "period_hours": hours,
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "attacker_sessions": attacker_count,
        "suspicious_sessions": suspicious_count,
        "total_credential_attempts": total_credentials,
        "total_canary_hits": total_canary_hits,
        "total_detections": total_detections,
        "avg_risk_score": round(float(avg_risk), 1),
    }), 200


@dashboard_bp.route("/stats/attack-types", methods=["GET"])
def attack_type_breakdown():
    """Breakdown of attack types (brute force vs SQLi vs port scan)."""
    hours = request.args.get("hours", 24, type=int)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    breakdown = db.session.query(
        DetectionLog.detection_type,
        func.count(DetectionLog.id),
    ).filter(
        DetectionLog.timestamp >= since,
    ).group_by(
        DetectionLog.detection_type,
    ).all()

    return jsonify({
        "attack_types": {dtype: count for dtype, count in breakdown},
        "period_hours": hours,
    }), 200


@dashboard_bp.route("/stats/geo", methods=["GET"])
def geo_distribution():
    """Geographic distribution of attackers."""
    hours = request.args.get("hours", 168, type=int)  # Default: 1 week
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    geo_data = db.session.query(
        AttackSession.geo_country,
        func.count(AttackSession.id),
    ).filter(
        AttackSession.created_at >= since,
        AttackSession.geo_country.isnot(None),
    ).group_by(
        AttackSession.geo_country,
    ).order_by(
        desc(func.count(AttackSession.id))
    ).limit(30).all()

    return jsonify({
        "countries": {country: count for country, count in geo_data},
        "period_hours": hours,
    }), 200


@dashboard_bp.route("/stats/timeline", methods=["GET"])
def attack_timeline():
    """Hourly attack count timeline for charting."""
    hours = request.args.get("hours", 24, type=int)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = AttackSession.query.filter(
        AttackSession.created_at >= since,
    ).order_by(AttackSession.created_at).all()

    # Bucket by hour
    timeline = {}
    for session in events:
        hour_key = session.created_at.strftime("%Y-%m-%d %H:00")
        if hour_key not in timeline:
            timeline[hour_key] = {"total": 0, "attacker": 0, "suspicious": 0, "legit": 0}
        timeline[hour_key]["total"] += 1
        action = (session.ml_action or "unknown").lower()
        if action in timeline[hour_key]:
            timeline[hour_key][action] += 1

    return jsonify({
        "timeline": timeline,
        "period_hours": hours,
    }), 200


# ── Sessions ─────────────────────────────────────────────────────────────


@dashboard_bp.route("/sessions", methods=["GET"])
def list_sessions():
    """
    List attack sessions with filtering and pagination.
    Query params: ?page=1&per_page=20&action=ATTACKER&status=active
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    action_filter = request.args.get("action")
    status_filter = request.args.get("status")

    query = AttackSession.query

    if action_filter:
        query = query.filter(AttackSession.ml_action == action_filter.upper())
    if status_filter:
        query = query.filter(AttackSession.status == status_filter)

    query = query.order_by(desc(AttackSession.created_at))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "sessions": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    }), 200


@dashboard_bp.route("/sessions/<session_id>", methods=["GET"])
def get_session_detail(session_id: str):
    """Get full details for a specific session including all related data."""
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    credentials = [c.to_dict() for c in session.credentials.order_by(
        CredentialAttempt.timestamp
    ).all()]

    commands = [c.to_dict() for c in session.shell_commands.order_by(
        ShellCommand.timestamp
    ).all()]

    canaries = [c.to_dict() for c in session.canary_hits.order_by(
        CanaryHit.timestamp
    ).all()]

    events = [e.to_dict() for e in session.events.order_by(
        SessionEvent.timestamp
    ).all()]

    result = session.to_dict()
    result.update({
        "credentials": credentials,
        "shell_commands": commands,
        "canary_hits": canaries,
        "events": events,
        "total_credentials": len(credentials),
        "total_commands": len(commands),
        "flags_raised": list({c["flag_raised"] for c in commands if c.get("flag_raised")}),
    })

    return jsonify(result), 200


@dashboard_bp.route("/sessions/<session_id>/timeline", methods=["GET"])
def session_timeline(session_id: str):
    """Get chronological event timeline for session replay."""
    session = AttackSession.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    events = session.events.order_by(SessionEvent.timestamp).all()

    return jsonify({
        "session_id": session_id,
        "events": [e.to_dict() for e in events],
        "total_events": len(events),
        "session_start": session.created_at.isoformat() if session.created_at else None,
        "duration_seconds": session.duration_seconds,
    }), 200


# ── Detection Logs ───────────────────────────────────────────────────────


@dashboard_bp.route("/detections", methods=["GET"])
def list_detections():
    """List recent detection events."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    detection_type = request.args.get("type")

    query = DetectionLog.query

    if detection_type:
        query = query.filter(DetectionLog.detection_type == detection_type.upper())

    query = query.order_by(desc(DetectionLog.timestamp))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "detections": [d.to_dict() for d in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
    }), 200


# ── Top Attackers ────────────────────────────────────────────────────────


@dashboard_bp.route("/stats/top-attackers", methods=["GET"])
def top_attackers():
    """Top attacking IPs by session count."""
    limit = request.args.get("limit", 10, type=int)

    top = db.session.query(
        AttackSession.attacker_ip,
        func.count(AttackSession.id).label("session_count"),
        func.max(AttackSession.risk_score).label("max_risk"),
        func.max(AttackSession.created_at).label("last_seen"),
    ).filter(
        AttackSession.ml_action == "ATTACKER",
    ).group_by(
        AttackSession.attacker_ip,
    ).order_by(
        desc("session_count")
    ).limit(limit).all()

    return jsonify({
        "top_attackers": [
            {
                "ip": ip,
                "session_count": count,
                "max_risk_score": max_risk,
                "last_seen": last_seen.isoformat() if last_seen else None,
            }
            for ip, count, max_risk, last_seen in top
        ],
    }), 200
