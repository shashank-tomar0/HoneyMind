"""
Login Classifier
================
Loads the trained model and runs inference on feature vectors to classify
login attempts as ATTACKER / SUSPICIOUS / LEGIT.

Confidence routing thresholds (configurable via config.yaml):
    Score >= 0.75   → ATTACKER   → activate honeypot
    Score 0.45–0.74 → SUSPICIOUS → log heavily, soft monitor
    Score < 0.45    → LEGIT      → allow through
"""

from __future__ import annotations

import logging
import pickle
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np

from .feature_extractor import FeatureExtractor, NUM_FEATURES

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

MODELS_DIR = Path(__file__).parent / "models"

PHASE1_MODEL_PATH = MODELS_DIR / "phase1_isolation.pkl"
PHASE2_MODEL_PATH = MODELS_DIR / "phase2_rf_latest.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

# Default confidence thresholds
DEFAULT_ATTACKER_THRESHOLD = 0.75
DEFAULT_SUSPICIOUS_THRESHOLD = 0.45


# ── Enums & Data Classes ──────────────────────────────────────────────────


class LoginAction(str, Enum):
    """Classification action for a login attempt."""
    ATTACKER = "ATTACKER"
    SUSPICIOUS = "SUSPICIOUS"
    LEGIT = "LEGIT"


@dataclass
class ClassificationResult:
    """Result of classifying a single login attempt."""
    action: LoginAction
    confidence: float
    phase: int                     # 1 = Isolation Forest, 2 = Random Forest
    feature_vector: np.ndarray = field(repr=False)
    raw_score: float = 0.0        # Pre-threshold raw model output

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "action": self.action.value,
            "confidence": round(self.confidence, 4),
            "phase": self.phase,
            "raw_score": round(self.raw_score, 4),
        }


# ── Classifier ─────────────────────────────────────────────────────────────


class LoginClassifier:
    """
    Two-phase login classifier.

    - **Phase 1** (Isolation Forest): unsupervised anomaly detection.
      Deployed from day 0 with zero labeled data.
    - **Phase 2** (Random Forest): supervised classification.
      Enabled automatically once a trained Phase 2 model is available.

    Usage::

        classifier = LoginClassifier()
        result = classifier.classify(session_dict)
        print(result.action, result.confidence)

    Parameters
    ----------
    attacker_threshold : float
        Minimum confidence to classify as ``ATTACKER`` (default 0.75).
    suspicious_threshold : float
        Minimum confidence to classify as ``SUSPICIOUS`` (default 0.45).
    force_phase : int or None
        Force the classifier to use a specific phase (1 or 2). If ``None``
        (default) the best available model is used automatically.
    """

    def __init__(
        self,
        attacker_threshold: float = DEFAULT_ATTACKER_THRESHOLD,
        suspicious_threshold: float = DEFAULT_SUSPICIOUS_THRESHOLD,
        force_phase: int | None = None,
    ) -> None:
        self.attacker_threshold = attacker_threshold
        self.suspicious_threshold = suspicious_threshold
        self.force_phase = force_phase

        self._extractor = FeatureExtractor()
        self._scaler = None
        self._phase1_model = None
        self._phase2_model = None
        self._active_phase: int = 0   # 0 = no model loaded

        self._load_models()

    # ── Model Loading ─────────────────────────────────────────────────

    def _load_models(self) -> None:
        """Load available models from disk."""
        # Load scaler
        if SCALER_PATH.exists():
            with open(SCALER_PATH, "rb") as f:
                self._scaler = pickle.load(f)
            logger.info("Loaded scaler from %s", SCALER_PATH)

        # Load Phase 2 (preferred if available)
        if PHASE2_MODEL_PATH.exists() and self.force_phase != 1:
            with open(PHASE2_MODEL_PATH, "rb") as f:
                self._phase2_model = pickle.load(f)
            self._active_phase = 2
            logger.info(
                "Loaded Phase 2 model (Random Forest) from %s",
                PHASE2_MODEL_PATH,
            )

        # Load Phase 1 (fallback or forced)
        if PHASE1_MODEL_PATH.exists():
            with open(PHASE1_MODEL_PATH, "rb") as f:
                self._phase1_model = pickle.load(f)
            if self._active_phase == 0 or self.force_phase == 1:
                self._active_phase = 1
            logger.info(
                "Loaded Phase 1 model (Isolation Forest) from %s",
                PHASE1_MODEL_PATH,
            )

        if self._active_phase == 0:
            logger.warning(
                "No trained models found in %s — classifier will return "
                "SUSPICIOUS for all inputs until a model is trained.",
                MODELS_DIR,
            )

    def reload_models(self) -> None:
        """Hot-reload models from disk (e.g. after retraining)."""
        self._phase1_model = None
        self._phase2_model = None
        self._scaler = None
        self._active_phase = 0
        self._load_models()

    # ── Classification ────────────────────────────────────────────────

    def classify(self, session: dict[str, Any]) -> ClassificationResult:
        """
        Classify a login session.

        Parameters
        ----------
        session : dict
            Raw login session dictionary (see ``FeatureExtractor``).

        Returns
        -------
        ClassificationResult
            Contains the action, confidence score, and active phase.
        """
        features = self._extractor.extract(session)
        return self._classify_features(features)

    def classify_batch(
        self, sessions: list[dict[str, Any]]
    ) -> list[ClassificationResult]:
        """Classify multiple sessions."""
        feature_matrix = self._extractor.extract_batch(sessions)
        return [self._classify_features(row) for row in feature_matrix]

    def _classify_features(self, features: np.ndarray) -> ClassificationResult:
        """Run classification on a pre-extracted feature vector."""
        if self._active_phase == 0:
            # No model — conservative default
            return ClassificationResult(
                action=LoginAction.SUSPICIOUS,
                confidence=0.50,
                phase=0,
                feature_vector=features,
                raw_score=0.50,
            )

        # Scale features if scaler is available
        scaled = features.reshape(1, -1)
        if self._scaler is not None:
            scaled = self._scaler.transform(scaled)

        if self._active_phase == 2:
            return self._predict_phase2(scaled, features)
        else:
            return self._predict_phase1(scaled, features)

    def _predict_phase1(
        self, scaled: np.ndarray, raw_features: np.ndarray
    ) -> ClassificationResult:
        """
        Phase 1 — Isolation Forest.

        Anomaly score is mapped to [0, 1] confidence:
            - score_samples() returns values in roughly [-1, 1]
            - More negative = more anomalous = higher attack confidence
        """
        raw_score = self._phase1_model.score_samples(scaled)[0]

        # Map: raw_score of -1.0 → confidence 1.0, raw_score of 0.5 → confidence 0.0
        # Clamp to [0, 1]
        confidence = float(np.clip((0.5 - raw_score) / 1.5, 0.0, 1.0))

        action = self._threshold_action(confidence)

        return ClassificationResult(
            action=action,
            confidence=confidence,
            phase=1,
            feature_vector=raw_features,
            raw_score=float(raw_score),
        )

    def _predict_phase2(
        self, scaled: np.ndarray, raw_features: np.ndarray
    ) -> ClassificationResult:
        """
        Phase 2 — Random Forest.

        Uses predict_proba() for the positive class (attacker) as confidence.
        """
        proba = self._phase2_model.predict_proba(scaled)[0]
        # proba[1] = probability of class 1 (attacker)
        confidence = float(proba[1]) if len(proba) > 1 else float(proba[0])

        action = self._threshold_action(confidence)

        return ClassificationResult(
            action=action,
            confidence=confidence,
            phase=2,
            feature_vector=raw_features,
            raw_score=confidence,
        )

    def _threshold_action(self, confidence: float) -> LoginAction:
        """Map a confidence score to the appropriate action."""
        if confidence >= self.attacker_threshold:
            return LoginAction.ATTACKER
        elif confidence >= self.suspicious_threshold:
            return LoginAction.SUSPICIOUS
        else:
            return LoginAction.LEGIT

    # ── Info ──────────────────────────────────────────────────────────

    @property
    def active_phase(self) -> int:
        """Return the currently active model phase (0, 1, or 2)."""
        return self._active_phase

    @property
    def is_ready(self) -> bool:
        """Whether at least one model is loaded."""
        return self._active_phase > 0

    def __repr__(self) -> str:
        return (
            f"LoginClassifier(phase={self._active_phase}, "
            f"attacker_thresh={self.attacker_threshold}, "
            f"suspicious_thresh={self.suspicious_threshold})"
        )
