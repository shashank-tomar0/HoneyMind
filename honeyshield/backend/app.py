"""
HoneyShield Flask Application Factory
======================================
Creates and configures the Flask application with all blueprints,
database initialization, and service wiring.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

from honeyshield.backend.config import FlaskConfig, load_config
from honeyshield.backend.models import db
from honeyshield.backend.sockets import socketio

logger = logging.getLogger(__name__)


def create_app(config_path: Optional[str] = None) -> Flask:
    """
    Flask application factory.

    Parameters
    ----------
    config_path : str, optional
        Path to config.yaml. Uses default if not provided.

    Returns
    -------
    Flask
        Configured Flask application.
    """
    app = Flask(
        __name__,
        static_folder="../fake_admin_panel/frontend",
        static_url_path="/"
    )

    # ── Load Configuration ────────────────────────────────────────────
    raw_config = load_config(config_path)
    flask_config = FlaskConfig(raw_config)
    app.config.from_object(flask_config)
    app.config["HONEYSHIELD_CONFIG"] = raw_config

    # ── CORS ──────────────────────────────────────────────────────────
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ── Database ──────────────────────────────────────────────────────
    db.init_app(app)

    with app.app_context():
        db.create_all()
        logger.info("Database tables created/verified.")

    # ── Initialize Detection Engine ───────────────────────────────────
    _init_detectors(app, raw_config)

    # ── Initialize ML Classifier ──────────────────────────────────────
    _init_ml_classifier(app, raw_config)

    # ── Register Blueprints ───────────────────────────────────────────
    _register_blueprints(app)

    # ── Health Check ──────────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health_check():
        classifier = app.config.get("ML_CLASSIFIER")
        return jsonify({
            "status": "healthy",
            "service": "HoneyShield",
            "version": "0.1.0",
            "ml_ready": classifier.is_ready if classifier else False,
            "ml_phase": classifier.active_phase if classifier else 0,
            "database": "connected",
        }), 200

    @app.route("/", methods=["GET"])
    def root():
        return app.send_static_file("index.html")

    # ── Init SocketIO (threading mode — no eventlet) ──────────────────
    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    logger.info("═" * 60)
    logger.info("  🐝 HoneyShield Flask Backend — Initialized")
    logger.info("═" * 60)

    return app


def _register_blueprints(app: Flask) -> None:
    """Register all route blueprints."""
    from honeyshield.backend.routes.auth import auth_bp
    from honeyshield.backend.routes.ml import ml_bp
    from honeyshield.backend.routes.dashboard import dashboard_bp
    from honeyshield.backend.routes.canary import canary_bp
    from honeyshield.backend.routes.intelligence import intelligence_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(canary_bp)
    app.register_blueprint(intelligence_bp)

    logger.info("Registered blueprints: auth, ml, dashboard, canary, intelligence")


def _init_detectors(app: Flask, config: dict) -> None:
    """Initialize detection engine components."""
    from honeyshield.detection_engine import (
        BruteForceDetector, SQLiDetector, PortScanDetector,
    )

    det_config = config.get("detection", {})

    detectors = {
        "brute_force": BruteForceDetector(
            max_attempts=det_config.get("brute_force_max_attempts", 5),
            time_window_s=det_config.get("brute_force_window_seconds", 60),
        ),
        "sqli": SQLiDetector(),
        "port_scan": PortScanDetector(
            max_ports=det_config.get("port_scan_max_ports", 5),
            time_window_s=det_config.get("port_scan_window_seconds", 10),
        ),
    }

    app.config["DETECTORS"] = detectors
    logger.info("Detection engine initialized: brute_force, sqli, port_scan")


def _init_ml_classifier(app: Flask, config: dict) -> None:
    """Initialize the ML classifier."""
    from honeyshield.ml_pipeline.classifier import LoginClassifier

    ml_config = config.get("ml_pipeline", {})

    try:
        classifier = LoginClassifier(
            attacker_threshold=ml_config.get("confidence_attacker_threshold", 0.75),
            suspicious_threshold=ml_config.get("confidence_suspicious_threshold", 0.45),
        )
        app.config["ML_CLASSIFIER"] = classifier
        logger.info(
            "ML Classifier initialized: phase=%d, ready=%s",
            classifier.active_phase, classifier.is_ready,
        )
    except Exception as e:
        logger.warning("ML Classifier failed to initialize: %s", e)
        app.config["ML_CLASSIFIER"] = None


# ── Entry Point ───────────────────────────────────────────────────────────


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(name)-35s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    app = create_app()
    port = app.config.get("HONEYSHIELD_CONFIG", {}).get("flask", {}).get("port", 5000)

    print()
    print("=" * 60)
    print("  🐝 HoneyShield Backend & WebSockets — Starting")
    print(f"  http://localhost:{port}")
    print("=" * 60)
    print()

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False,
        allow_unsafe_werkzeug=True,
    )
