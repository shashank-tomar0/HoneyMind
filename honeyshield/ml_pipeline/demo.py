#!/usr/bin/env python3
"""
HoneyShield ML Pipeline — Demo & Validation Script
====================================================
Trains both phases, runs classification on synthetic test data,
and outputs evaluation metrics + charts.

Usage:
    python -m honeyshield.ml_pipeline.demo
"""

import logging
import sys
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-30s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("honeyshield.demo")


def main():
    from honeyshield.ml_pipeline.trainer import (
        ModelTrainer,
        generate_synthetic_legit_sessions,
        generate_synthetic_attacker_sessions,
    )
    from honeyshield.ml_pipeline.classifier import LoginClassifier
    from honeyshield.ml_pipeline.evaluator import ModelEvaluator
    from honeyshield.ml_pipeline.label_store import LabelStore
    from honeyshield.ml_pipeline.feature_extractor import FeatureExtractor

    print()
    print("=" * 70)
    print("  🐝 HoneyShield ML Pipeline — Demo & Validation")
    print("=" * 70)
    print()

    trainer = ModelTrainer()

    # ── Phase 1: Train Isolation Forest ──────────────────────────────
    print("\n▓▓▓ PHASE 1: Isolation Forest (Unsupervised) ▓▓▓\n")
    phase1_meta = trainer.train_phase1(use_synthetic=True)
    print(f"  ✓ Phase 1 trained on {phase1_meta['training_samples']} synthetic samples")
    print(f"  ✓ Model: {phase1_meta['model_path']}")

    # ── Phase 2: Train Random Forest ─────────────────────────────────
    print("\n▓▓▓ PHASE 2: Random Forest (Supervised) ▓▓▓\n")
    phase2_meta = trainer.train_phase2(use_synthetic=True)
    print(f"  ✓ Phase 2 trained — Test accuracy: {phase2_meta['test_accuracy']:.4f}")
    print(f"  ✓ Model: {phase2_meta['model_path']}")
    print(f"\n  Top features:")
    for name, imp in list(phase2_meta["feature_importances"].items())[:5]:
        print(f"    {name:30s}  {imp:.4f}")

    # ── Load Classifier & Test ───────────────────────────────────────
    print("\n▓▓▓ CLASSIFICATION TESTS ▓▓▓\n")
    classifier = LoginClassifier()
    print(f"  Active phase: {classifier.active_phase}")

    # Test 1: Obvious attacker session
    attacker_session = {
        "time_to_submit_form_s": 0.3,
        "attempts_per_minute": 45,
        "is_vpn": True,
        "is_tor": True,
        "ip_abuse_score": 85,
        "username": "admin",
        "password": "123456",
        "user_agent": "python-requests/2.28",
        "has_javascript": False,
        "mouse_moved_before_click": False,
        "keystroke_interval_ms": 12.0,
        "request_hour": 3,
    }
    result = classifier.classify(attacker_session)
    print(f"\n  Test 1 — Obvious Bot Attack:")
    print(f"    Action:     {result.action.value}")
    print(f"    Confidence: {result.confidence:.4f}")
    print(f"    Phase:      {result.phase}")

    # Test 2: Legitimate user session
    legit_session = {
        "time_to_submit_form_s": 6.2,
        "attempts_per_minute": 1,
        "is_vpn": False,
        "is_tor": False,
        "ip_abuse_score": 3,
        "username": "john.doe",
        "password": "MyStr0ngP@ss!2024",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "has_javascript": True,
        "mouse_moved_before_click": True,
        "keystroke_interval_ms": 145.0,
        "request_hour": 10,
    }
    result = classifier.classify(legit_session)
    print(f"\n  Test 2 — Legitimate Human User:")
    print(f"    Action:     {result.action.value}")
    print(f"    Confidence: {result.confidence:.4f}")
    print(f"    Phase:      {result.phase}")

    # Test 3: Suspicious / borderline session
    suspicious_session = {
        "time_to_submit_form_s": 2.1,
        "attempts_per_minute": 8,
        "is_vpn": True,
        "is_tor": False,
        "ip_abuse_score": 35,
        "username": "root",
        "password": "S3cureP@ss!",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "has_javascript": True,
        "mouse_moved_before_click": True,
        "keystroke_interval_ms": 55.0,
        "request_hour": 22,
    }
    result = classifier.classify(suspicious_session)
    print(f"\n  Test 3 — Suspicious / Borderline:")
    print(f"    Action:     {result.action.value}")
    print(f"    Confidence: {result.confidence:.4f}")
    print(f"    Phase:      {result.phase}")

    # ── Evaluate on Test Set ─────────────────────────────────────────
    print("\n▓▓▓ MODEL EVALUATION ▓▓▓\n")
    evaluator = ModelEvaluator()

    # Generate test data
    X_test_legit = generate_synthetic_legit_sessions(200)
    X_test_attack = generate_synthetic_attacker_sessions(50)
    X_test = np.vstack([X_test_legit, X_test_attack])
    y_test = np.concatenate([np.zeros(200), np.ones(50)])

    report = evaluator.evaluate(X_test, y_test, phase=2)
    print(f"  Accuracy:  {report['accuracy']:.4f}")
    print(f"  Precision: {report['precision']:.4f}")
    print(f"  Recall:    {report['recall']:.4f}")
    print(f"  F1 Score:  {report['f1_score']:.4f}")
    print(f"  ROC AUC:   {report['roc_auc']:.4f}")
    print(f"\n  Confusion Matrix:")
    cm = report["confusion_matrix"]
    print(f"    {'':>10s} Pred Legit  Pred Attack")
    print(f"    {'Legit':>10s}     {cm[0][0]:>4d}        {cm[0][1]:>4d}")
    print(f"    {'Attacker':>10s}     {cm[1][0]:>4d}        {cm[1][1]:>4d}")

    # Save charts
    try:
        cm_path = evaluator.save_confusion_matrix(X_test, y_test, phase=2)
        fi_path = evaluator.save_feature_importance(phase=2)
        roc_path = evaluator.save_roc_curve(X_test, y_test, phase=2)
        print(f"\n  Charts saved:")
        print(f"    ✓ {cm_path}")
        print(f"    ✓ {fi_path}")
        print(f"    ✓ {roc_path}")
    except Exception as e:
        print(f"\n  ⚠ Chart generation skipped: {e}")

    # ── Label Store Demo ─────────────────────────────────────────────
    print("\n▓▓▓ LABEL STORE ▓▓▓\n")
    store = LabelStore()
    extractor = FeatureExtractor()

    # Add a flagged session
    features = extractor.extract(attacker_session)
    sid = store.add_unlabeled(attacker_session, features, ml_score=0.91)
    print(f"  Added unlabeled session: {sid}")

    # Label it
    store.label_session(sid, label=1, labeled_by="demo")
    print(f"  Labeled as ATTACKER")

    stats = store.stats()
    print(f"  Store stats: {stats}")

    print("\n" + "=" * 70)
    print("  ✅ ML Pipeline validated successfully!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
