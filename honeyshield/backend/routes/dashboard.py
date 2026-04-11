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


@dashboard_bp.route("/stats/devices", methods=["GET"])
def device_footprints():
    """Device footprint categorization from user agents."""
    hours = request.args.get("hours", 24, type=int)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    sessions = AttackSession.query.filter(
        AttackSession.created_at >= since,
        AttackSession.ml_action != "LEGIT"
    ).all()

    devices = {
        "Windows": 0,
        "macOS": 0,
        "Linux": 0,
        "Mobile": 0,
        "Automated Scripts / Bots": 0,
        "Tor Network": 0,
        "Unknown / Malformed": 0
    }

    for s in sessions:
        if s.is_tor:
            devices["Tor Network"] += 1
            continue

        ua = (s.user_agent or "").lower()

        if not ua or "undefined" in ua:
            devices["Unknown / Malformed"] += 1
        elif "nmap" in ua or "curl" in ua or "python" in ua or "bot" in ua or "request" in ua or "wget" in ua or "masscan" in ua:
            devices["Automated Scripts / Bots"] += 1
        elif "android" in ua or "iphone" in ua or "ipad" in ua:
            devices["Mobile"] += 1
        elif "windows" in ua:
            devices["Windows"] += 1
        elif "mac os" in ua or "macintosh" in ua:
            devices["macOS"] += 1
        elif "linux" in ua or "x11" in ua:
            devices["Linux"] += 1
        else:
            devices["Unknown / Malformed"] += 1

    return jsonify({
        "devices": devices,
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


# ── Attackers (full view, excludes LEGIT) ────────────────────────────────


@dashboard_bp.route("/attackers", methods=["GET"])
def list_attackers():
    """
    List all attackers from the database, aggregated by IP.
    Excludes LEGIT (LOW risk) sessions.
    Returns geo, canary intel, event counts, and attack types.
    """
    from honeyshield.backend.geolocation import geolocate_ip

    # Get all non-LEGIT sessions
    sessions = AttackSession.query.filter(
        AttackSession.ml_action != "LEGIT",
    ).order_by(desc(AttackSession.created_at)).all()

    # Aggregate by IP
    ip_map = {}
    for s in sessions:
        ip = s.attacker_ip or "unknown"
        if ip not in ip_map:
            geo = geolocate_ip(ip)
            resolved_ip = geo.get("resolved_ip") or ip
            ip_map[ip] = {
                "ip": resolved_ip,
                "raw_ip": ip,
                "threat_level": s.ml_action or "MEDIUM",
                "threat_score": int((s.ml_confidence or 0.5) * 100),
                "country": s.geo_country or geo.get("country", "Unknown"),
                "country_code": geo.get("country_code", "XX"),
                "city": s.geo_city or geo.get("city", "Unknown"),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
                "lat": geo.get("lat", 0),
                "lng": geo.get("lng", 0),
                "attack_types": set(),
                "session_ids": [],
                "event_count": 0,
                "credential_count": 0,
                "first_seen": s.created_at.isoformat() if s.created_at else None,
                "last_seen": s.created_at.isoformat() if s.created_at else None,
                "canary_hits": [],
                "user_agents": set(),
                "is_vpn": False,
                "is_tor": False,
                "_js_sum": 0, "_js_count": 0,
                "_mouse_sum": 0, "_mouse_count": 0,
                "_key_sum": 0, "_key_count": 0,
                "_time_sum": 0, "_time_count": 0,
            }

        entry = ip_map[ip]
        
        if s.created_at:
            s_iso = s.created_at.isoformat()
            if not entry["first_seen"] or s_iso < entry["first_seen"]:
                entry["first_seen"] = s_iso
            if not entry["last_seen"] or s_iso > entry["last_seen"]:
                entry["last_seen"] = s_iso

        entry["session_ids"].append(s.id)
        entry["event_count"] += (s.events.count() if hasattr(s, 'events') else 0)
        entry["credential_count"] += (s.credentials.count() if hasattr(s, 'credentials') else 0)

        if getattr(s, "user_agent", None):
            entry["user_agents"].add(s.user_agent)
        if s.is_vpn: entry["is_vpn"] = True
        if s.is_tor: entry["is_tor"] = True

        for cred in s.credentials:
            if getattr(cred, "has_javascript", None) is not None:
                entry["_js_sum"] += 1 if cred.has_javascript else 0
                entry["_js_count"] += 1
            if getattr(cred, "mouse_moved", None) is not None:
                entry["_mouse_sum"] += 1 if cred.mouse_moved else 0
                entry["_mouse_count"] += 1
            if getattr(cred, "keystroke_interval_ms", None) is not None:
                entry["_key_sum"] += cred.keystroke_interval_ms
                entry["_key_count"] += 1
            if getattr(cred, "time_to_submit_s", None) is not None:
                entry["_time_sum"] += cred.time_to_submit_s
                entry["_time_count"] += 1

        # Use highest threat level
        level_priority = {"ATTACKER": 3, "SUSPICIOUS": 2, "MEDIUM": 1}
        if level_priority.get(s.ml_action, 0) > level_priority.get(entry["threat_level"], 0):
            entry["threat_level"] = s.ml_action
        entry["threat_score"] = max(entry["threat_score"], int((s.ml_confidence or 0.5) * 100))

        # Collect attack types from detections
        detections = DetectionLog.query.filter_by(session_id=s.id).all()
        for det in detections:
            entry["attack_types"].add(det.detection_type)
            
        # Also include any flags attached directly to the session config
        if getattr(s, "detection_flags", None):
            try:
                flags = s.detection_flags
                if isinstance(flags, str):
                    import json
                    flags = json.loads(flags)
                for f in flags:
                    entry["attack_types"].add(f)
            except Exception:
                pass

        # Track time range
        if s.created_at:
            ts = s.created_at.isoformat()
            if ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if ts > entry["last_seen"]:
                entry["last_seen"] = ts

    # Attach canary hits
    canary_hits = CanaryHit.query.order_by(desc(CanaryHit.timestamp)).all()
    for hit in canary_hits:
        if hit.session_id:
            # Find which IP this session belongs to
            for ip, data in ip_map.items():
                if hit.session_id in data["session_ids"]:
                    geo = geolocate_ip(hit.real_ip)
                    data["canary_hits"].append({
                        "real_ip": geo.get("resolved_ip") or hit.real_ip,
                        "city": geo.get("city", "Unknown"),
                        "country": geo.get("country", "Unknown"),
                        "isp": geo.get("isp", ""),
                        "org": geo.get("org", ""),
                        "lat": geo.get("lat", 0),
                        "lng": geo.get("lng", 0),
                        "file": hit.bait_file_name,
                        "timestamp": hit.timestamp.isoformat() if hit.timestamp else None,
                    })
                    break

    # Build response, converting sets to lists
    result = []
    for ip, data in ip_map.items():
        data["attack_types"] = list(data["attack_types"])
        if not data["attack_types"]:
            data["attack_types"] = ["CREDENTIAL_ATTACK"]
        data["session_count"] = len(data["session_ids"])
        
        # Format custom device lists
        data["user_agents"] = list(data["user_agents"])
        
        # Calculate behavioral metrics
        data["has_javascript"] = (data["_js_sum"] / data["_js_count"] >= 0.5) if data["_js_count"] > 0 else False
        data["mouse_moved"] = (data["_mouse_sum"] / data["_mouse_count"] >= 0.5) if data["_mouse_count"] > 0 else False
        data["avg_keystroke_ms"] = round(data["_key_sum"] / data["_key_count"], 1) if data["_key_count"] > 0 else 0
        data["avg_time_submit_s"] = round(data["_time_sum"] / data["_time_count"], 2) if data["_time_count"] > 0 else 0
        
        # Cleanup internals
        del data["session_ids"]
        del data["_js_sum"]
        del data["_js_count"]
        del data["_mouse_sum"]
        del data["_mouse_count"]
        del data["_key_sum"]
        del data["_key_count"]
        del data["_time_sum"]
        del data["_time_count"]
        
        result.append(data)

    # Sort by threat level priority
    level_sort = {"ATTACKER": 3, "SUSPICIOUS": 2}
    result.sort(key=lambda x: level_sort.get(x["threat_level"], 0), reverse=True)

    return jsonify({"attackers": result, "total": len(result)}), 200


@dashboard_bp.route("/attackers/<path:ip>", methods=["DELETE"])
def delete_attacker(ip: str):
    """
    Deletes all records of an attacker IP entirely from the database.
    Due to foreign key constraints lacking automatic cascading, we wipe manually.
    """
    sessions = AttackSession.query.filter_by(attacker_ip=ip).all()
    if not sessions:
        return jsonify({"error": "Attacker IP not found in telemetry records"}), 404

    session_ids = [s.id for s in sessions]

    # Manually execute hard cascade deletion across connected forensic tables
    CredentialAttempt.query.filter(CredentialAttempt.session_id.in_(session_ids)).delete(synchronize_session=False)
    ShellCommand.query.filter(ShellCommand.session_id.in_(session_ids)).delete(synchronize_session=False)
    CanaryHit.query.filter(CanaryHit.session_id.in_(session_ids)).delete(synchronize_session=False)
    SessionEvent.query.filter(SessionEvent.session_id.in_(session_ids)).delete(synchronize_session=False)
    
    # DetectionLogs are created independently by the engine and often lack session_ids
    DetectionLog.query.filter_by(ip=ip).delete(synchronize_session=False)

    # Nuke the parent node
    AttackSession.query.filter_by(attacker_ip=ip).delete(synchronize_session=False)
    
    db.session.commit()

    return jsonify({"status": "success", "message": f"Wiped forensic telemetry belonging to {ip}"}), 200

