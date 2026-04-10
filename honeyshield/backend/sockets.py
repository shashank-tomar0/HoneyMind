"""
WebSocket Handlers for Analyst Dashboard
========================================
Bridges Flask-SocketIO with the React frontend to stream live attack traffic,
session snapshots, and periodic statistics.
"""

import time
import logging
import threading
import random
from flask_socketio import SocketIO, emit
from honeyshield.backend.models import db, AttackSession

logger = logging.getLogger(__name__)

socketio = SocketIO(cors_allowed_origins="*")

# Background thread to simulate live attacks if real traffic is low
_simulation_thread = None
_thread_lock = threading.Lock()

def _get_live_stats():
    """Calculate live statistics from the real database."""
    from honeyshield.backend.models import CredentialAttempt, SessionEvent, DetectionLog

    total = AttackSession.query.count()
    active = AttackSession.query.filter(AttackSession.status != "COMPLETED").count()
    total_events = SessionEvent.query.count()
    total_creds = CredentialAttempt.query.count()
    total_detections = DetectionLog.query.count()

    # Calculate real avg threat score
    sessions = AttackSession.query.filter(AttackSession.ml_confidence.isnot(None)).all()
    avg_score = 0
    if sessions:
        avg_score = round(sum(s.ml_confidence or 0 for s in sessions) / len(sessions) * 10, 1)

    # Get attack vector distribution
    detection_types = db.session.query(
        DetectionLog.detection_type, db.func.count(DetectionLog.id)
    ).group_by(DetectionLog.detection_type).all()
    attack_vectors = {dt: count for dt, count in detection_types}

    return {
        "total_sessions": total,
        "active_sessions": active,
        "avg_threat_score": avg_score,
        "total_events": total_events + total_creds + total_detections,
        "attack_vectors": attack_vectors,
    }

def _get_live_sessions():
    """Get active sessions from the real database."""
    from honeyshield.backend.geolocation import geolocate_ip

    sessions = AttackSession.query.order_by(AttackSession.created_at.desc()).limit(15).all()

    res = []
    for s in sessions:
        # Use stored geo data, or resolve from IP if not available
        if s.geo_country and s.geo_country != "Unknown":
            geo = {
                "lat": 20.59,  # Default if not stored
                "lng": 78.96,
                "country": s.geo_country,
                "country_code": "XX",
                "city": s.geo_city or "Unknown",
            }
        else:
            geo = geolocate_ip(s.attacker_ip)

        res.append({
            "session_id": s.id,
            "start_time": s.created_at.isoformat() if s.created_at else None,
            "threat_score": int((s.ml_confidence or 0.5) * 10),
            "threat_level": s.ml_action or "LOW",
            "geo": {
                "lat": geo["lat"],
                "lng": geo["lng"],
                "country": geo["country"],
                "country_code": geo.get("country_code", "XX"),
                "city": geo.get("city", "Unknown"),
            },
            "attacker_ip": geo.get("resolved_ip") or s.attacker_ip,
            "is_active": s.status != "COMPLETED"
        })
    return res

@socketio.on("connect")
def handle_connect():
    logger.info("Dashboard Frontend connected to WebSocket.")
    # TURNED OFF BACKGROUND SIMULATOR FOR PURE REAL-TRAFFIC
    # global _simulation_thread
    # with _thread_lock:
        # if _simulation_thread is None:
            # _simulation_thread = socketio.start_background_task(_background_simulator)

@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Dashboard Frontend disconnected from WebSocket.")

@socketio.on("request_stats")
def handle_request_stats():
    emit("stats_update", _get_live_stats())

@socketio.on("request_sessions")
def handle_request_sessions():
    emit("sessions_snapshot", _get_live_sessions())

def _background_simulator():
    """
    Constantly pumps simulated attack data into the websocket so the
    React UI's Globe and Feed look alive, augmenting real DB traffic.
    """
    logger.info("Starting background WebSocket simulator thread.")
    
    attack_types = ['SSH Brute Force', 'SQL Injection', 'Canary Trigger', 'Port Scan']
    levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    while True:
        time.sleep(random.uniform(1.5, 4.0)) # Emit event every 1.5 - 4s
        
        # 1. Generate Fake Live Event for the Globe
        event = {
            "session_id": f"sim-{random.randint(1000, 9999)}",
            "timestamp": time.time(),
            "attack_type": random.choice(attack_types),
            "threat_level": random.choice(levels),
            "threat_score": random.randint(4, 10),
            "payload": f"Simulated payload data",
            "geo": {
                "lat": random.uniform(-50, 70),
                "lng": random.uniform(-130, 150),
                "country": ["Russia", "China", "Brazil", "USA", "Germany", "Iran"][random.randint(0,5)]
            },
            "attacker_ip": f"{random.randint(10,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "classification_confidence": round(random.uniform(0.65, 0.99), 2),
            "is_anomaly": random.random() > 0.8
        }
        
        # Push to React Dashboard
        socketio.emit("attack_event", event)
        socketio.emit("stats_update", _get_live_stats())
        
        if event["is_anomaly"]:
            socketio.emit("anomaly_alert", {
                "type": "New Zero-day signature",
                "description": f"Anomalous pattern from {event['geo']['country']}",
                "severity": event["threat_level"]
            })
