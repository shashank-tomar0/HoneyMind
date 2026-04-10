"""
Model Trainer
=============
Handles training for both phases of the ML pipeline:
    - Phase 1: Isolation Forest (unsupervised anomaly detection)
    - Phase 2: Random Forest (supervised binary classification)

Also provides:
    - Scheduled weekly retraining via the ``schedule`` library
    - Synthetic data generation for bootstrapping Phase 1
    - Model serialization to ``models/`` directory
"""

from __future__ import annotations

import logging
import pickle
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .feature_extractor import FeatureExtractor, NUM_FEATURES, FEATURE_NAMES

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────

MODELS_DIR = Path(__file__).parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

PHASE1_MODEL_PATH = MODELS_DIR / "phase1_isolation.pkl"
PHASE2_MODEL_PATH = MODELS_DIR / "phase2_rf_latest.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

# ── Default Hyperparameters ────────────────────────────────────────────────

PHASE1_CONTAMINATION = 0.05       # Expected fraction of anomalies
PHASE1_N_ESTIMATORS = 200
PHASE1_RANDOM_STATE = 42

PHASE2_N_ESTIMATORS = 300
PHASE2_MAX_DEPTH = 15
PHASE2_MIN_SAMPLES_SPLIT = 5
PHASE2_RANDOM_STATE = 42
PHASE2_MIN_LABELED_SAMPLES = 500  # Minimum labeled sessions for Phase 2

TEST_SPLIT_RATIO = 0.2

# ── Synthetic Data Generator ──────────────────────────────────────────────


def generate_synthetic_legit_sessions(n: int = 1000) -> np.ndarray:
    """
    Generate synthetic *legitimate* login sessions for bootstrapping
    Phase 1 training when no real data exists yet.

    The distributions are calibrated to mimic typical human behavior:
        - Form submission time: 3–12 seconds (normal distribution)
        - Low attempts per minute
        - No VPN/TOR
        - Low abuse scores
        - Natural keystroke intervals
        - Normal working hours

    Parameters
    ----------
    n : int
        Number of synthetic sessions to generate.

    Returns
    -------
    numpy.ndarray
        Shape ``(n, 12)`` feature matrix.
    """
    rng = np.random.default_rng(seed=42)
    data = np.zeros((n, NUM_FEATURES), dtype=np.float64)

    # 0: time_to_submit_form_s — human: 3-12s, normal distribution
    data[:, 0] = rng.normal(loc=6.0, scale=2.0, size=n).clip(1.5, 20.0)

    # 1: attempts_per_minute — legit: 0-2
    data[:, 1] = rng.poisson(lam=0.5, size=n).clip(0, 5).astype(float)

    # 2: is_vpn — ~10% of legit users use VPN
    data[:, 2] = (rng.random(n) < 0.10).astype(float)

    # 3: is_tor — nearly 0% for legit
    data[:, 3] = (rng.random(n) < 0.01).astype(float)

    # 4: ip_abuse_score — legit: 0-15
    data[:, 4] = rng.integers(0, 15, size=n).astype(float)

    # 5: username_is_common — ~5% legit users use common usernames
    data[:, 5] = (rng.random(n) < 0.05).astype(float)

    # 6: password_in_wordlist — ~3% legit users use common passwords
    data[:, 6] = (rng.random(n) < 0.03).astype(float)

    # 7: user_agent_is_headless — 0% for legit
    data[:, 7] = np.zeros(n)

    # 8: has_javascript — ~98% for legit
    data[:, 8] = (rng.random(n) < 0.98).astype(float)

    # 9: mouse_moved_before_click — ~95% for legit
    data[:, 9] = (rng.random(n) < 0.95).astype(float)

    # 10: keystroke_interval_ms — human: 80-250ms, normal distribution
    data[:, 10] = rng.normal(loc=150.0, scale=40.0, size=n).clip(50, 400)

    # 11: request_hour — working hours centered around 10-18
    data[:, 11] = rng.normal(loc=14.0, scale=3.0, size=n).clip(0, 23).astype(int)

    return data


def generate_synthetic_attacker_sessions(n: int = 200) -> np.ndarray:
    """
    Generate synthetic *attacker* sessions for Phase 2 bootstrapping.

    Mimics bot/script-kiddie behavior:
        - Very fast form submission
        - High attempt rates
        - VPN/TOR usage
        - Headless browsers
        - No JS, no mouse, uniform keystroke timing
    """
    rng = np.random.default_rng(seed=99)
    data = np.zeros((n, NUM_FEATURES), dtype=np.float64)

    # 0: time_to_submit_form_s — bots: 0.1-1.5s
    data[:, 0] = rng.uniform(0.05, 1.5, size=n)

    # 1: attempts_per_minute — bots: 10-60
    data[:, 1] = rng.integers(10, 60, size=n).astype(float)

    # 2: is_vpn — ~70% attackers use VPN
    data[:, 2] = (rng.random(n) < 0.70).astype(float)

    # 3: is_tor — ~30% use TOR
    data[:, 3] = (rng.random(n) < 0.30).astype(float)

    # 4: ip_abuse_score — attackers: 40-100
    data[:, 4] = rng.integers(40, 100, size=n).astype(float)

    # 5: username_is_common — ~85% use common usernames
    data[:, 5] = (rng.random(n) < 0.85).astype(float)

    # 6: password_in_wordlist — ~70% use wordlist passwords
    data[:, 6] = (rng.random(n) < 0.70).astype(float)

    # 7: user_agent_is_headless — ~60% headless
    data[:, 7] = (rng.random(n) < 0.60).astype(float)

    # 8: has_javascript — ~20% bots execute JS
    data[:, 8] = (rng.random(n) < 0.20).astype(float)

    # 9: mouse_moved_before_click — ~5% bots simulate mouse
    data[:, 9] = (rng.random(n) < 0.05).astype(float)

    # 10: keystroke_interval_ms — bots: 5-30ms, very uniform
    data[:, 10] = rng.uniform(5, 30, size=n)

    # 11: request_hour — attacks peak 1-5 AM
    data[:, 11] = rng.choice([0, 1, 2, 3, 4, 5, 22, 23], size=n).astype(float)

    return data


# ── Model Trainer ──────────────────────────────────────────────────────────


class ModelTrainer:
    """
    Trains and persists ML models for the HoneyShield pipeline.

    Usage::

        trainer = ModelTrainer()

        # Phase 1 — from day 0, no labels needed
        trainer.train_phase1(legit_sessions=[...])

        # Phase 2 — after collecting 500+ labeled sessions
        trainer.train_phase2(labeled_sessions=[...], labels=[...])

        # Start scheduled retraining
        trainer.start_scheduled_retrain(
            data_loader=my_data_loader_fn,
            schedule_cron="monday 02:00"
        )
    """

    def __init__(self) -> None:
        self._extractor = FeatureExtractor()
        self._scaler: StandardScaler | None = None
        self._retrain_thread: threading.Thread | None = None
        self._stop_retrain = threading.Event()

    # ── Phase 1: Isolation Forest ─────────────────────────────────────

    def train_phase1(
        self,
        legit_sessions: list[dict[str, Any]] | None = None,
        legit_features: np.ndarray | None = None,
        contamination: float = PHASE1_CONTAMINATION,
        n_estimators: int = PHASE1_N_ESTIMATORS,
        use_synthetic: bool = True,
    ) -> dict[str, Any]:
        """
        Train the Phase 1 Isolation Forest on legitimate sessions.

        If no data is provided and ``use_synthetic=True``, synthetic
        legitimate sessions are generated for bootstrapping.

        Parameters
        ----------
        legit_sessions : list of dict, optional
            Raw session dicts for legitimate users.
        legit_features : numpy.ndarray, optional
            Pre-extracted feature matrix. Takes precedence over sessions.
        contamination : float
            Expected proportion of anomalies in the training data.
        n_estimators : int
            Number of trees in the Isolation Forest.
        use_synthetic : bool
            Whether to generate synthetic data if no real data is provided.

        Returns
        -------
        dict
            Training metadata including model path and data shape.
        """
        logger.info("═" * 60)
        logger.info("Training Phase 1 — Isolation Forest")
        logger.info("═" * 60)

        # Prepare feature matrix
        if legit_features is not None:
            X = legit_features
        elif legit_sessions:
            X = self._extractor.extract_batch(legit_sessions)
        elif use_synthetic:
            logger.info("No real data provided — generating synthetic legit sessions")
            X = generate_synthetic_legit_sessions(n=1000)
        else:
            raise ValueError(
                "No training data: provide legit_sessions, legit_features, "
                "or set use_synthetic=True"
            )

        logger.info("Training data shape: %s", X.shape)

        # Fit scaler
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train Isolation Forest
        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=PHASE1_RANDOM_STATE,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        # Persist
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        with open(PHASE1_MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self._scaler, f)

        logger.info("Phase 1 model saved to %s", PHASE1_MODEL_PATH)
        logger.info("Scaler saved to %s", SCALER_PATH)

        metadata = {
            "phase": 1,
            "model": "IsolationForest",
            "n_estimators": n_estimators,
            "contamination": contamination,
            "training_samples": X.shape[0],
            "features": X.shape[1],
            "model_path": str(PHASE1_MODEL_PATH),
            "scaler_path": str(SCALER_PATH),
            "timestamp": datetime.utcnow().isoformat(),
        }
        logger.info("Phase 1 training complete: %s", metadata)
        return metadata

    # ── Phase 2: Random Forest ────────────────────────────────────────

    def train_phase2(
        self,
        labeled_sessions: list[dict[str, Any]] | None = None,
        labels: list[int] | None = None,
        feature_matrix: np.ndarray | None = None,
        label_array: np.ndarray | None = None,
        n_estimators: int = PHASE2_N_ESTIMATORS,
        max_depth: int = PHASE2_MAX_DEPTH,
        min_samples_split: int = PHASE2_MIN_SAMPLES_SPLIT,
        use_synthetic: bool = True,
    ) -> dict[str, Any]:
        """
        Train the Phase 2 Random Forest on labeled data.

        Parameters
        ----------
        labeled_sessions : list of dict, optional
            Raw session dicts.
        labels : list of int, optional
            Labels: 0 = legit, 1 = attacker. Must match ``labeled_sessions``.
        feature_matrix : numpy.ndarray, optional
            Pre-extracted feature matrix. Takes precedence.
        label_array : numpy.ndarray, optional
            Pre-formed label array.
        n_estimators, max_depth, min_samples_split : int
            Random Forest hyperparameters.
        use_synthetic : bool
            Generate synthetic data if real data is insufficient.

        Returns
        -------
        dict
            Training metadata including accuracy, confusion matrix, and path.
        """
        logger.info("═" * 60)
        logger.info("Training Phase 2 — Random Forest")
        logger.info("═" * 60)

        # Prepare features + labels
        if feature_matrix is not None and label_array is not None:
            X = feature_matrix
            y = np.asarray(label_array)
        elif labeled_sessions and labels:
            X = self._extractor.extract_batch(labeled_sessions)
            y = np.array(labels)
        elif use_synthetic:
            logger.info("Generating synthetic data for Phase 2 bootstrap")
            X_legit = generate_synthetic_legit_sessions(n=800)
            y_legit = np.zeros(800, dtype=int)
            X_attack = generate_synthetic_attacker_sessions(n=200)
            y_attack = np.ones(200, dtype=int)
            X = np.vstack([X_legit, X_attack])
            y = np.concatenate([y_legit, y_attack])
        else:
            raise ValueError(
                "No training data: provide labeled_sessions+labels, "
                "feature_matrix+label_array, or set use_synthetic=True"
            )

        if len(X) < PHASE2_MIN_LABELED_SAMPLES and not use_synthetic:
            logger.warning(
                "Only %d labeled samples (minimum %d recommended). "
                "Model quality may be poor.",
                len(X),
                PHASE2_MIN_LABELED_SAMPLES,
            )

        logger.info("Training data: %d samples (%d legit, %d attacker)",
                     len(y), (y == 0).sum(), (y == 1).sum())

        # Scale
        if self._scaler is None:
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)
            with open(SCALER_PATH, "wb") as f:
                pickle.dump(self._scaler, f)
        else:
            X_scaled = self._scaler.transform(X)

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=TEST_SPLIT_RATIO,
            random_state=PHASE2_RANDOM_STATE, stratify=y,
        )

        # Train Random Forest
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            class_weight="balanced",
            random_state=PHASE2_RANDOM_STATE,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)

        # Evaluate on held-out test set
        train_acc = float(model.score(X_train, y_train))
        test_acc = float(model.score(X_test, y_test))

        # Feature importances
        importances = dict(zip(FEATURE_NAMES, model.feature_importances_))

        # Persist model
        with open(PHASE2_MODEL_PATH, "wb") as f:
            pickle.dump(model, f)

        logger.info("Phase 2 model saved to %s", PHASE2_MODEL_PATH)

        metadata = {
            "phase": 2,
            "model": "RandomForest",
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "training_samples": len(y_train),
            "test_samples": len(y_test),
            "train_accuracy": round(train_acc, 4),
            "test_accuracy": round(test_acc, 4),
            "feature_importances": {
                k: round(v, 4) for k, v in
                sorted(importances.items(), key=lambda x: x[1], reverse=True)
            },
            "model_path": str(PHASE2_MODEL_PATH),
            "timestamp": datetime.utcnow().isoformat(),
        }
        logger.info("Phase 2 training complete. Test accuracy: %.4f", test_acc)
        return metadata

    # ── Scheduled Retraining ──────────────────────────────────────────

    def start_scheduled_retrain(
        self,
        data_loader: callable,
        interval_hours: float = 168,  # Weekly by default
    ) -> None:
        """
        Start a background thread that periodically retrains Phase 2.

        Parameters
        ----------
        data_loader : callable
            A function that returns ``(feature_matrix, label_array)``
            when called — fetches the latest labeled data from the DB.
        interval_hours : float
            Hours between retraining runs (default 168 = 1 week).
        """
        if self._retrain_thread and self._retrain_thread.is_alive():
            logger.warning("Retrain scheduler already running.")
            return

        self._stop_retrain.clear()

        def _retrain_loop():
            logger.info(
                "Retrain scheduler started (every %.1f hours)", interval_hours
            )
            while not self._stop_retrain.is_set():
                self._stop_retrain.wait(timeout=interval_hours * 3600)
                if self._stop_retrain.is_set():
                    break
                try:
                    logger.info("Scheduled retrain triggered")
                    X, y = data_loader()
                    if X is not None and len(X) >= PHASE2_MIN_LABELED_SAMPLES:
                        self.train_phase2(
                            feature_matrix=X,
                            label_array=y,
                            use_synthetic=False,
                        )
                    else:
                        logger.info(
                            "Not enough labeled data for retrain (%d samples)",
                            len(X) if X is not None else 0,
                        )
                except Exception:
                    logger.exception("Scheduled retrain failed")

        self._retrain_thread = threading.Thread(
            target=_retrain_loop, daemon=True, name="ml-retrain-scheduler"
        )
        self._retrain_thread.start()

    def stop_scheduled_retrain(self) -> None:
        """Stop the background retraining scheduler."""
        self._stop_retrain.set()
        if self._retrain_thread:
            self._retrain_thread.join(timeout=5)
            logger.info("Retrain scheduler stopped.")
