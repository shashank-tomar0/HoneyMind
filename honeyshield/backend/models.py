"""
HoneyShield Flask Backend — Database Models
============================================
SQLAlchemy models for persisting attack sessions, canary hits,
detection events, and ML classification results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Attack Session ────────────────────────────────────────────────────────


class AttackSession(db.Model):
    """
    Represents a complete attacker engagement session.
    One session = one attacker from entry to exit.
    """
    __tablename__ = "attack_sessions"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    # Source info
    attacker_ip = db.Column(db.String(45), nullable=False, index=True)
    real_ip_via_canary = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    is_vpn = db.Column(db.Boolean, default=False)
    is_tor = db.Column(db.Boolean, default=False)

    # Geolocation
    geo_city = db.Column(db.String(100), nullable=True)
    geo_region = db.Column(db.String(100), nullable=True)
    geo_country = db.Column(db.String(100), nullable=True)
    geo_isp = db.Column(db.String(200), nullable=True)

    # ML Classification
    ml_action = db.Column(db.String(20), nullable=True)   # ATTACKER/SUSPICIOUS/LEGIT
    ml_confidence = db.Column(db.Float, nullable=True)
    ml_phase = db.Column(db.Integer, nullable=True)

    # Detection flags
    detection_flags = db.Column(db.JSON, default=list)     # ["BRUTE_FORCE", "SQLI", ...]

    # Session data
    status = db.Column(db.String(20), default="active")    # active/completed/expired
    duration_seconds = db.Column(db.Float, nullable=True)
    services_probed = db.Column(db.JSON, default=list)     # ["ssh", "ftp", "admin_panel"]

    # Scores
    risk_score = db.Column(db.Integer, default=0)          # 1-10
    ip_abuse_score = db.Column(db.Integer, default=0)      # 0-100

    # Relationships
    credentials = db.relationship("CredentialAttempt", backref="session", lazy="dynamic")
    shell_commands = db.relationship("ShellCommand", backref="session", lazy="dynamic")
    canary_hits = db.relationship("CanaryHit", backref="session", lazy="dynamic")
    events = db.relationship("SessionEvent", backref="session", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "attacker_ip": self.attacker_ip,
            "real_ip_via_canary": self.real_ip_via_canary,
            "user_agent": self.user_agent,
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
            "geolocation": {
                "city": self.geo_city,
                "region": self.geo_region,
                "country": self.geo_country,
                "isp": self.geo_isp,
            },
            "ml_action": self.ml_action,
            "ml_confidence": self.ml_confidence,
            "ml_phase": self.ml_phase,
            "detection_flags": self.detection_flags or [],
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "services_probed": self.services_probed or [],
            "risk_score": self.risk_score,
            "ip_abuse_score": self.ip_abuse_score,
        }


# ── Credential Attempt ───────────────────────────────────────────────────


class CredentialAttempt(db.Model):
    """Records every username/password pair tried during a session."""
    __tablename__ = "credential_attempts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("attack_sessions.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow)

    username = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(500), nullable=False)  # Store for analysis — it's a honeypot
    was_granted = db.Column(db.Boolean, default=False)
    ip = db.Column(db.String(45), nullable=True)

    # Behavioral signals captured during this attempt
    time_to_submit_s = db.Column(db.Float, nullable=True)
    keystroke_interval_ms = db.Column(db.Float, nullable=True)
    mouse_moved = db.Column(db.Boolean, nullable=True)
    has_javascript = db.Column(db.Boolean, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "username": self.username,
            "password": self.password,
            "was_granted": self.was_granted,
            "time_to_submit_s": self.time_to_submit_s,
            "keystroke_interval_ms": self.keystroke_interval_ms,
            "mouse_moved": self.mouse_moved,
        }


# ── Shell Command ────────────────────────────────────────────────────────


class ShellCommand(db.Model):
    """Records every command entered in fake SSH sessions."""
    __tablename__ = "shell_commands"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("attack_sessions.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow)

    command = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)
    flag_raised = db.Column(db.String(50), nullable=True)  # e.g., ATTEMPTED_DOWNLOAD
    flag_detail = db.Column(db.Text, nullable=True)         # e.g., URL captured

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "command": self.command,
            "response": self.response,
            "flag_raised": self.flag_raised,
            "flag_detail": self.flag_detail,
        }


# ── Canary Hit ───────────────────────────────────────────────────────────


class CanaryHit(db.Model):
    """Records when a canary token bait file is opened by the attacker."""
    __tablename__ = "canary_hits"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("attack_sessions.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=utcnow)

    token_id = db.Column(db.String(36), nullable=False, index=True)
    bait_file_type = db.Column(db.String(10), nullable=True)  # html, xlsx, pdf
    bait_file_name = db.Column(db.String(200), nullable=True)

    # Identity captured from the callback
    real_ip = db.Column(db.String(45), nullable=False)
    real_user_agent = db.Column(db.Text, nullable=True)
    real_referrer = db.Column(db.Text, nullable=True)
    real_geo_country = db.Column(db.String(100), nullable=True)
    real_geo_city = db.Column(db.String(100), nullable=True)
    real_isp = db.Column(db.String(200), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "token_id": self.token_id,
            "bait_file_type": self.bait_file_type,
            "bait_file_name": self.bait_file_name,
            "real_ip": self.real_ip,
            "real_user_agent": self.real_user_agent,
            "real_geo_country": self.real_geo_country,
            "real_geo_city": self.real_geo_city,
            "real_isp": self.real_isp,
        }


# ── Session Event ────────────────────────────────────────────────────────


class SessionEvent(db.Model):
    """
    Generic event log for anything that happens during a session.
    Used for timeline reconstruction and session replay.
    """
    __tablename__ = "session_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("attack_sessions.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)

    event_type = db.Column(db.String(50), nullable=False)  # LOGIN_ATTEMPT, COMMAND, DOWNLOAD, etc.
    event_data = db.Column(db.JSON, default=dict)
    source_service = db.Column(db.String(30), nullable=True)  # ssh, ftp, admin_panel
    severity = db.Column(db.String(20), default="INFO")        # INFO, WARNING, CRITICAL

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "source_service": self.source_service,
            "severity": self.severity,
        }


# ── Detection Log ────────────────────────────────────────────────────────


class DetectionLog(db.Model):
    """Logs every detection engine trigger (brute force, SQLi, port scan)."""
    __tablename__ = "detection_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)

    ip = db.Column(db.String(45), nullable=False, index=True)
    detection_type = db.Column(db.String(30), nullable=False)  # BRUTE_FORCE, SQL_INJECTION, PORT_SCAN
    severity = db.Column(db.String(20), default="HIGH")
    details = db.Column(db.JSON, default=dict)
    session_id = db.Column(db.String(36), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip": self.ip,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "details": self.details,
            "session_id": self.session_id,
        }


# ── Legitimate User ─────────────────────────────────────────────────────


class LegitUser(db.Model):
    """
    Legitimate users who are allowed through the honeypot to the real app.
    Stored in the database instead of hardcoded credentials.
    """
    __tablename__ = "users_database"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(50), default="user")  # admin, analyst, user
    email = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password: str) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "email": self.email,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

