"""
Label Store
===========
Persistent store for ML-flagged sessions awaiting manual labeling.

Phase 1 (Isolation Forest) flags anomalous sessions but cannot confirm
whether they're truly attackers. This module:
    1. Stores flagged sessions with their feature vectors
    2. Allows manual labeling (0 = legit, 1 = attacker)
    3. Exports labeled data for Phase 2 training

Storage: JSON-lines file on disk (no external DB dependency).
Can be upgraded to PostgreSQL via the database layer later.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────

DATA_DIR = Path(__file__).parent / "label_data"
UNLABELED_FILE = DATA_DIR / "unlabeled_sessions.jsonl"
LABELED_FILE = DATA_DIR / "labeled_sessions.jsonl"


# ── Label Store ────────────────────────────────────────────────────────────


class LabelStore:
    """
    Manages the lifecycle of flagged sessions from detection to labeling.

    Workflow::

        store = LabelStore()

        # 1. Phase 1 flags a session as anomalous
        store.add_unlabeled(session_data, features, ml_score=0.82)

        # 2. Analyst reviews and labels
        store.label_session(session_id, label=1)  # 1 = attacker

        # 3. Export for Phase 2 training
        X, y = store.export_training_data()
    """

    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Add Unlabeled Session ────────────────────────────────────────

    def add_unlabeled(
        self,
        session: dict[str, Any],
        features: np.ndarray,
        ml_score: float,
        ml_phase: int = 1,
    ) -> str:
        """
        Store a flagged session for later manual labeling.

        Parameters
        ----------
        session : dict
            The raw session data (IP, username, UA, etc.).
        features : numpy.ndarray
            The 12-dim feature vector extracted for this session.
        ml_score : float
            The ML confidence score that flagged this session.
        ml_phase : int
            Which ML phase flagged this (1 or 2).

        Returns
        -------
        str
            A unique session_id for reference.
        """
        session_id = str(uuid.uuid4())

        record = {
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ml_score": round(ml_score, 4),
            "ml_phase": ml_phase,
            "features": features.tolist(),
            "session_data": _sanitize_session(session),
            "label": None,       # Not yet labeled
            "labeled_at": None,
            "labeled_by": None,
        }

        with open(UNLABELED_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        logger.info(
            "Stored unlabeled session %s (score=%.4f, phase=%d)",
            session_id, ml_score, ml_phase,
        )
        return session_id

    # ── Label a Session ──────────────────────────────────────────────

    def label_session(
        self,
        session_id: str,
        label: int,
        labeled_by: str = "analyst",
    ) -> bool:
        """
        Apply a manual label to a previously flagged session.

        Parameters
        ----------
        session_id : str
            The session ID returned by ``add_unlabeled``.
        label : int
            0 = legit, 1 = attacker.
        labeled_by : str
            Identifier of the person/system applying the label.

        Returns
        -------
        bool
            True if the session was found and labeled, False otherwise.
        """
        if label not in (0, 1):
            raise ValueError(f"Label must be 0 (legit) or 1 (attacker), got {label}")

        # Read all unlabeled records
        if not UNLABELED_FILE.exists():
            logger.warning("No unlabeled sessions file found.")
            return False

        records = []
        found = False
        target_record = None

        with open(UNLABELED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record["session_id"] == session_id:
                    found = True
                    record["label"] = label
                    record["labeled_at"] = datetime.now(timezone.utc).isoformat()
                    record["labeled_by"] = labeled_by
                    target_record = record
                else:
                    records.append(record)

        if not found:
            logger.warning("Session %s not found in unlabeled store.", session_id)
            return False

        # Write the labeled record to labeled file
        with open(LABELED_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(target_record) + "\n")

        # Rewrite unlabeled file without the labeled session
        with open(UNLABELED_FILE, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

        logger.info(
            "Labeled session %s as %s by %s",
            session_id,
            "ATTACKER" if label == 1 else "LEGIT",
            labeled_by,
        )
        return True

    # ── Bulk Label ───────────────────────────────────────────────────

    def label_batch(
        self,
        labels: dict[str, int],
        labeled_by: str = "analyst",
    ) -> int:
        """
        Label multiple sessions at once.

        Parameters
        ----------
        labels : dict
            Mapping of ``{session_id: label}`` (0 or 1).
        labeled_by : str
            Who is labeling.

        Returns
        -------
        int
            Number of sessions successfully labeled.
        """
        labeled_count = 0
        for sid, lbl in labels.items():
            if self.label_session(sid, lbl, labeled_by):
                labeled_count += 1
        return labeled_count

    # ── Export Training Data ─────────────────────────────────────────

    def export_training_data(self) -> tuple[np.ndarray | None, np.ndarray | None]:
        """
        Export all labeled sessions as training data for Phase 2.

        Returns
        -------
        tuple of (numpy.ndarray, numpy.ndarray) or (None, None)
            Feature matrix ``X`` and label array ``y``, or ``(None, None)``
            if no labeled data exists.
        """
        if not LABELED_FILE.exists():
            logger.info("No labeled data file found.")
            return None, None

        features_list = []
        labels_list = []

        with open(LABELED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("label") is not None:
                    features_list.append(record["features"])
                    labels_list.append(record["label"])

        if not features_list:
            logger.info("No labeled sessions found in labeled file.")
            return None, None

        X = np.array(features_list, dtype=np.float64)
        y = np.array(labels_list, dtype=int)

        logger.info(
            "Exported %d labeled sessions (%d legit, %d attacker)",
            len(y), (y == 0).sum(), (y == 1).sum(),
        )
        return X, y

    # ── Statistics ───────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return counts of unlabeled and labeled sessions."""
        unlabeled_count = 0
        if UNLABELED_FILE.exists():
            with open(UNLABELED_FILE, "r", encoding="utf-8") as f:
                unlabeled_count = sum(1 for line in f if line.strip())

        labeled_count = 0
        legit_count = 0
        attacker_count = 0
        if LABELED_FILE.exists():
            with open(LABELED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    labeled_count += 1
                    if record.get("label") == 0:
                        legit_count += 1
                    elif record.get("label") == 1:
                        attacker_count += 1

        return {
            "unlabeled": unlabeled_count,
            "labeled": labeled_count,
            "legit": legit_count,
            "attacker": attacker_count,
            "ready_for_phase2": labeled_count >= 500,
        }

    # ── List Unlabeled ───────────────────────────────────────────────

    def list_unlabeled(
        self, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        List unlabeled sessions for manual review.

        Parameters
        ----------
        limit : int
            Maximum number of records to return.
        offset : int
            Number of records to skip.

        Returns
        -------
        list of dict
            Unlabeled session records (without raw feature arrays for readability).
        """
        if not UNLABELED_FILE.exists():
            return []

        results = []
        with open(UNLABELED_FILE, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i < offset:
                    continue
                if len(results) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                # Return a summary view (exclude full feature vector)
                results.append({
                    "session_id": record["session_id"],
                    "timestamp": record["timestamp"],
                    "ml_score": record["ml_score"],
                    "ml_phase": record["ml_phase"],
                    "ip": record.get("session_data", {}).get("ip", "unknown"),
                    "username": record.get("session_data", {}).get("username", "unknown"),
                })

        return results


# ── Helpers ────────────────────────────────────────────────────────────────


def _sanitize_session(session: dict[str, Any]) -> dict[str, Any]:
    """
    Create a JSON-serializable copy of the session, stripping
    non-serializable values.
    """
    sanitized = {}
    for key, value in session.items():
        if isinstance(value, (str, int, float, bool, type(None))):
            sanitized[key] = value
        elif isinstance(value, (list, tuple)):
            sanitized[key] = list(value)
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_session(value)
        elif isinstance(value, np.ndarray):
            sanitized[key] = value.tolist()
        else:
            sanitized[key] = str(value)
    return sanitized
