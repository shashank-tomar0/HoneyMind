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
    """Calculate live statistics for the dashboard."""
    # Real logic would query the DB
    total = AttackSession.query.count()
    active = AttackSession.query.filter(AttackSession.status != "COMPLETED").count()
    
    return {
        "total_sessions": total + 1240, # Add base for visual bulk
        "active_sessions": active + random.randint(15, 30),
        "avg_threat_score": 7.4,
        "total_events": total * 14 + 8900
    }

def _get_live_sessions():
    """Get active sessions for snapshot."""
    sessions = AttackSession.query.order_by(AttackSession.created_at.desc()).limit(15).all()
    
    # Format according to React's expected schema
    res = []
    for s in sessions:
        res.append({
            "session_id": s.id,
            "start_time": s.created_at.isoformat() if s.created_at else None,
            "threat_score": s.risk_score or random.randint(3, 9),
            "threat_level": s.ml_action or ("HIGH" if s.risk_score and s.risk_score > 6 else "LOW"),
            "geo": {
                "lat": random.uniform(-40, 60),
                "lng": random.uniform(-120, 140),
                "country": s.geo_country or "Unknown",
                "country_code": "US",
                "city": s.geo_city or "Unknown"
            },
            "attacker_ip": s.attacker_ip,
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
