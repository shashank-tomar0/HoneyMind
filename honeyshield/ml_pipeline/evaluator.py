"""
Model Evaluator
===============
Generates evaluation metrics, confusion matrices, classification reports,
and feature importance charts for the trained ML models.

Produces:
    - Confusion matrix (console + saved PNG)
    - Classification report (precision, recall, F1)
    - Feature importance bar chart (Phase 2 only)
    - ROC curve and AUC score
"""

from __future__ import annotations

import logging
import pickle
from io import StringIO
from pathlib import Path
from typing import Any

import numpy as np

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from .feature_extractor import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────

MODELS_DIR = Path(__file__).parent / "models"
REPORTS_DIR = Path(__file__).parent / "evaluation_reports"


# ── Evaluator ──────────────────────────────────────────────────────────────


class ModelEvaluator:
    """
    Evaluates trained HoneyShield ML models and generates reports.

    Usage::

        evaluator = ModelEvaluator()

        # Evaluate Phase 2 model on test data
        report = evaluator.evaluate(X_test, y_test, phase=2)
        print(report)

        # Generate and save charts
        evaluator.save_confusion_matrix(X_test, y_test, phase=2)
        evaluator.save_feature_importance(phase=2)
        evaluator.save_roc_curve(X_test, y_test, phase=2)
    """

    def __init__(self) -> None:
        self._phase1_model = None
        self._phase2_model = None
        self._scaler = None
        self._load_models()

    def _load_models(self) -> None:
        """Load trained models from disk."""
        phase1_path = MODELS_DIR / "phase1_isolation.pkl"
        phase2_path = MODELS_DIR / "phase2_rf_latest.pkl"
        scaler_path = MODELS_DIR / "scaler.pkl"

        if scaler_path.exists():
            with open(scaler_path, "rb") as f:
                self._scaler = pickle.load(f)

        if phase1_path.exists():
            with open(phase1_path, "rb") as f:
                self._phase1_model = pickle.load(f)

        if phase2_path.exists():
            with open(phase2_path, "rb") as f:
                self._phase2_model = pickle.load(f)

    # ── Main Evaluation ───────────────────────────────────────────────

    def evaluate(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        phase: int = 2,
    ) -> dict[str, Any]:
        """
        Run full evaluation on the specified model phase.

        Parameters
        ----------
        X : numpy.ndarray
            Feature matrix, shape ``(n_samples, 12)``.
        y_true : numpy.ndarray
            Ground truth labels (0 = legit, 1 = attacker).
        phase : int
            Which model phase to evaluate (1 or 2).

        Returns
        -------
        dict
            Comprehensive evaluation metrics.
        """
        model = self._get_model(phase)

        # Scale features
        X_scaled = self._scaler.transform(X) if self._scaler else X

        if phase == 1:
            return self._evaluate_phase1(model, X_scaled, y_true)
        else:
            return self._evaluate_phase2(model, X_scaled, y_true)

    def _evaluate_phase1(
        self, model, X_scaled: np.ndarray, y_true: np.ndarray
    ) -> dict[str, Any]:
        """Evaluate Phase 1 Isolation Forest."""
        # Isolation Forest: predict returns 1 (inlier) or -1 (outlier)
        predictions = model.predict(X_scaled)
        # Map: -1 (outlier/anomaly) → 1 (attacker), 1 (inlier) → 0 (legit)
        y_pred = np.where(predictions == -1, 1, 0)

        scores = model.score_samples(X_scaled)

        report = {
            "phase": 1,
            "model": "IsolationForest",
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": classification_report(
                y_true, y_pred,
                target_names=["legit", "attacker"],
                zero_division=0,
            ),
            "anomaly_score_stats": {
                "mean": float(scores.mean()),
                "std": float(scores.std()),
                "min": float(scores.min()),
                "max": float(scores.max()),
            },
            "samples_evaluated": len(y_true),
        }

        logger.info("Phase 1 Evaluation — Accuracy: %.4f, F1: %.4f",
                     report["accuracy"], report["f1_score"])
        return report

    def _evaluate_phase2(
        self, model, X_scaled: np.ndarray, y_true: np.ndarray
    ) -> dict[str, Any]:
        """Evaluate Phase 2 Random Forest."""
        y_pred = model.predict(X_scaled)
        y_proba = model.predict_proba(X_scaled)[:, 1]

        auc = float(roc_auc_score(y_true, y_proba))

        # Feature importances
        importances = dict(zip(FEATURE_NAMES, model.feature_importances_))
        sorted_importances = {
            k: round(v, 4)
            for k, v in sorted(importances.items(), key=lambda x: x[1], reverse=True)
        }

        report = {
            "phase": 2,
            "model": "RandomForest",
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "roc_auc": auc,
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": classification_report(
                y_true, y_pred,
                target_names=["legit", "attacker"],
                zero_division=0,
            ),
            "feature_importances": sorted_importances,
            "samples_evaluated": len(y_true),
        }

        logger.info(
            "Phase 2 Evaluation — Accuracy: %.4f, F1: %.4f, AUC: %.4f",
            report["accuracy"], report["f1_score"], auc,
        )
        return report

    # ── Chart Generation ──────────────────────────────────────────────

    def save_confusion_matrix(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        phase: int = 2,
        output_path: str | Path | None = None,
    ) -> Path:
        """
        Generate and save a confusion matrix heatmap as PNG.

        Parameters
        ----------
        X : numpy.ndarray
            Feature matrix.
        y_true : numpy.ndarray
            Ground truth labels.
        phase : int
            Model phase (1 or 2).
        output_path : str or Path, optional
            Custom output path. Defaults to ``evaluation_reports/``.

        Returns
        -------
        Path
            Path to the saved PNG file.
        """
        try:
            import matplotlib
            matplotlib.use("Agg")  # Non-interactive backend
            import matplotlib.pyplot as plt
            import seaborn as sns
        except ImportError:
            logger.warning(
                "matplotlib/seaborn not installed — skipping chart generation"
            )
            return Path()

        model = self._get_model(phase)
        X_scaled = self._scaler.transform(X) if self._scaler else X

        if phase == 1:
            preds = model.predict(X_scaled)
            y_pred = np.where(preds == -1, 1, 0)
        else:
            y_pred = model.predict(X_scaled)

        cm = confusion_matrix(y_true, y_pred)

        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Legit", "Attacker"],
            yticklabels=["Legit", "Attacker"],
            ax=ax,
        )
        ax.set_xlabel("Predicted", fontsize=12)
        ax.set_ylabel("Actual", fontsize=12)
        ax.set_title(f"HoneyShield — Phase {phase} Confusion Matrix", fontsize=14)

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            output_path = REPORTS_DIR / f"confusion_matrix_phase{phase}.png"
        else:
            output_path = Path(output_path)

        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        logger.info("Confusion matrix saved to %s", output_path)
        return output_path

    def save_feature_importance(
        self,
        phase: int = 2,
        output_path: str | Path | None = None,
    ) -> Path:
        """
        Generate and save a feature importance bar chart (Phase 2 only).

        Returns
        -------
        Path
            Path to the saved PNG file.
        """
        if phase != 2:
            logger.warning("Feature importance chart only available for Phase 2.")
            return Path()

        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            logger.warning("matplotlib not installed — skipping chart generation")
            return Path()

        model = self._get_model(2)
        importances = model.feature_importances_

        # Sort by importance
        indices = np.argsort(importances)[::-1]
        sorted_names = [FEATURE_NAMES[i] for i in indices]
        sorted_values = importances[indices]

        fig, ax = plt.subplots(figsize=(10, 6))
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(sorted_names)))
        ax.barh(range(len(sorted_names)), sorted_values, color=colors)
        ax.set_yticks(range(len(sorted_names)))
        ax.set_yticklabels(sorted_names, fontsize=10)
        ax.set_xlabel("Importance", fontsize=12)
        ax.set_title("HoneyShield — Feature Importance (Phase 2 RF)", fontsize=14)
        ax.invert_yaxis()

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            output_path = REPORTS_DIR / "feature_importance_phase2.png"
        else:
            output_path = Path(output_path)

        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        logger.info("Feature importance chart saved to %s", output_path)
        return output_path

    def save_roc_curve(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        phase: int = 2,
        output_path: str | Path | None = None,
    ) -> Path:
        """
        Generate and save an ROC curve plot (Phase 2 only).

        Returns
        -------
        Path
            Path to the saved PNG file.
        """
        if phase != 2:
            logger.warning("ROC curve only available for Phase 2.")
            return Path()

        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            logger.warning("matplotlib not installed — skipping chart generation")
            return Path()

        model = self._get_model(2)
        X_scaled = self._scaler.transform(X) if self._scaler else X
        y_proba = model.predict_proba(X_scaled)[:, 1]

        fpr, tpr, thresholds = roc_curve(y_true, y_proba)
        auc = roc_auc_score(y_true, y_proba)

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot(fpr, tpr, color="#2196F3", lw=2,
                label=f"ROC curve (AUC = {auc:.4f})")
        ax.plot([0, 1], [0, 1], color="gray", linestyle="--", lw=1)
        ax.set_xlabel("False Positive Rate", fontsize=12)
        ax.set_ylabel("True Positive Rate", fontsize=12)
        ax.set_title("HoneyShield — ROC Curve (Phase 2 RF)", fontsize=14)
        ax.legend(loc="lower right", fontsize=11)
        ax.grid(alpha=0.3)

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            output_path = REPORTS_DIR / "roc_curve_phase2.png"
        else:
            output_path = Path(output_path)

        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        logger.info("ROC curve saved to %s (AUC=%.4f)", output_path, auc)
        return output_path

    # ── Helpers ───────────────────────────────────────────────────────

    def _get_model(self, phase: int):
        """Get the model for a given phase, or raise."""
        if phase == 1:
            if self._phase1_model is None:
                raise FileNotFoundError(
                    "Phase 1 model not found. Train it first with ModelTrainer."
                )
            return self._phase1_model
        elif phase == 2:
            if self._phase2_model is None:
                raise FileNotFoundError(
                    "Phase 2 model not found. Train it first with ModelTrainer."
                )
            return self._phase2_model
        else:
            raise ValueError(f"Invalid phase: {phase}. Must be 1 or 2.")
