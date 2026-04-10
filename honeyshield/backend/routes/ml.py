"""
ML Pipeline Routes
==================
API endpoints for the ML classification system:
    - Classify a session
    - Train models
    - Get model status
    - Manage labels
    - Get evaluation reports
"""

from __future__ import annotations

import logging
from flask import Blueprint, request, jsonify, current_app

from honeyshield.ml_pipeline.trainer import ModelTrainer
from honeyshield.ml_pipeline.label_store import LabelStore
from honeyshield.ml_pipeline.evaluator import ModelEvaluator
from honeyshield.ml_pipeline.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

ml_bp = Blueprint("ml", __name__, url_prefix="/api/ml")


@ml_bp.route("/status", methods=["GET"])
def ml_status():
    """Get the current ML pipeline status."""
    classifier = current_app.config.get("ML_CLASSIFIER")
    label_store = LabelStore()

    return jsonify({
        "active_phase": classifier.active_phase if classifier else 0,
        "is_ready": classifier.is_ready if classifier else False,
        "attacker_threshold": classifier.attacker_threshold if classifier else None,
        "suspicious_threshold": classifier.suspicious_threshold if classifier else None,
        "label_stats": label_store.stats(),
    }), 200


@ml_bp.route("/classify", methods=["POST"])
def classify_session():
    """
    Classify a login session.

    Body: Raw session dict with features.
    """
    data = request.get_json(force=True, silent=True) or {}
    classifier = current_app.config.get("ML_CLASSIFIER")

    if not classifier or not classifier.is_ready:
        return jsonify({"error": "ML classifier not ready"}), 503

    result = classifier.classify(data)
    return jsonify(result.to_dict()), 200


@ml_bp.route("/classify/batch", methods=["POST"])
def classify_batch():
    """Classify multiple sessions at once."""
    data = request.get_json(force=True, silent=True) or {}
    sessions = data.get("sessions", [])

    if not sessions:
        return jsonify({"error": "No sessions provided"}), 400

    classifier = current_app.config.get("ML_CLASSIFIER")
    if not classifier or not classifier.is_ready:
        return jsonify({"error": "ML classifier not ready"}), 503

    results = classifier.classify_batch(sessions)
    return jsonify({
        "results": [r.to_dict() for r in results],
        "count": len(results),
    }), 200


@ml_bp.route("/train/phase1", methods=["POST"])
def train_phase1():
    """
    Train Phase 1 (Isolation Forest).
    Optional body: {"use_synthetic": true}
    """
    data = request.get_json(force=True, silent=True) or {}
    use_synthetic = data.get("use_synthetic", True)

    trainer = ModelTrainer()
    try:
        metadata = trainer.train_phase1(use_synthetic=use_synthetic)

        # Reload classifier
        classifier = current_app.config.get("ML_CLASSIFIER")
        if classifier:
            classifier.reload_models()

        return jsonify({
            "status": "success",
            "metadata": metadata,
        }), 200
    except Exception as e:
        logger.exception("Phase 1 training failed")
        return jsonify({"error": str(e)}), 500


@ml_bp.route("/train/phase2", methods=["POST"])
def train_phase2():
    """
    Train Phase 2 (Random Forest).
    Uses labeled data from label store, or synthetic if insufficient.
    """
    data = request.get_json(force=True, silent=True) or {}
    use_synthetic = data.get("use_synthetic", True)

    trainer = ModelTrainer()
    label_store = LabelStore()

    # Try to use real labeled data
    X, y = label_store.export_training_data()
    if X is not None and len(X) >= 500:
        metadata = trainer.train_phase2(
            feature_matrix=X, label_array=y, use_synthetic=False
        )
    elif use_synthetic:
        metadata = trainer.train_phase2(use_synthetic=True)
    else:
        stats = label_store.stats()
        return jsonify({
            "error": f"Insufficient labeled data ({stats['labeled']} samples, need 500)",
            "label_stats": stats,
        }), 400

    # Reload classifier
    classifier = current_app.config.get("ML_CLASSIFIER")
    if classifier:
        classifier.reload_models()

    return jsonify({
        "status": "success",
        "metadata": metadata,
    }), 200


@ml_bp.route("/labels", methods=["GET"])
def list_unlabeled():
    """List unlabeled sessions pending review."""
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    store = LabelStore()
    sessions = store.list_unlabeled(limit=limit, offset=offset)

    return jsonify({
        "sessions": sessions,
        "stats": store.stats(),
    }), 200


@ml_bp.route("/labels/<session_id>", methods=["PUT"])
def label_session(session_id: str):
    """
    Label a session.
    Body: {"label": 0 or 1, "labeled_by": "analyst"}
    """
    data = request.get_json(force=True, silent=True) or {}
    label = data.get("label")
    labeled_by = data.get("labeled_by", "analyst")

    if label not in (0, 1):
        return jsonify({"error": "Label must be 0 (legit) or 1 (attacker)"}), 400

    store = LabelStore()
    success = store.label_session(session_id, label=label, labeled_by=labeled_by)

    if success:
        return jsonify({"status": "labeled", "session_id": session_id}), 200
    else:
        return jsonify({"error": "Session not found"}), 404


@ml_bp.route("/labels/batch", methods=["PUT"])
def label_batch():
    """
    Label multiple sessions.
    Body: {"labels": {"session_id": 0_or_1, ...}, "labeled_by": "analyst"}
    """
    data = request.get_json(force=True, silent=True) or {}
    labels = data.get("labels", {})
    labeled_by = data.get("labeled_by", "analyst")

    if not labels:
        return jsonify({"error": "No labels provided"}), 400

    store = LabelStore()
    count = store.label_batch(labels, labeled_by=labeled_by)

    return jsonify({
        "status": "success",
        "labeled_count": count,
        "stats": store.stats(),
    }), 200


@ml_bp.route("/features", methods=["POST"])
def extract_features():
    """
    Extract features from a session (debugging/inspection).
    Body: Raw session dict.
    """
    data = request.get_json(force=True, silent=True) or {}
    extractor = FeatureExtractor()
    features = extractor.extract(data)

    return jsonify({
        "features": dict(zip(extractor.feature_names(), features.tolist())),
        "raw": features.tolist(),
    }), 200
