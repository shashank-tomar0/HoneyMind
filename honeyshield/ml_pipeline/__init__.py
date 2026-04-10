"""
HoneyShield ML Pipeline
========================
Core classification engine that decides whether a login attempt
is from an attacker, suspicious user, or legitimate user.

Two-Phase Strategy:
    Phase 1 - Isolation Forest (unsupervised, deploy from day 0)
    Phase 2 - Random Forest (supervised, after ~500 labeled sessions)
"""

from .feature_extractor import FeatureExtractor
from .classifier import LoginClassifier, ClassificationResult
from .trainer import ModelTrainer
from .evaluator import ModelEvaluator
from .label_store import LabelStore

__all__ = [
    "FeatureExtractor",
    "LoginClassifier",
    "ClassificationResult",
    "ModelTrainer",
    "ModelEvaluator",
    "LabelStore",
]
