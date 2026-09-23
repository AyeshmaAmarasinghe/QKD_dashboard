"""Risk inputs for the AI control plane, each carrying explicit provenance.

Every quantity here is either produced by a loaded research artifact or is a
stated, non-learned fallback.  Nothing is fabricated: when an input cannot be
produced it is ``None`` and its status string says why, so the UI can show
"Unavailable" rather than a reassuring zero.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from dashboard.runtime import notebook_runtime as nr

# Status vocabulary used across the UI for the network model.
NET_AVAILABLE = "AVAILABLE_AND_ENABLED"
NET_MISSING = "MISSING"
NET_INCOMPATIBLE = "INCOMPATIBLE"
NET_REJECTED = "REJECTED_BY_RELIABILITY_GATE"
NET_FALLBACK = "QKD_ONLY_FALLBACK"

SOURCE_TRAINED = "trained artifact"
SOURCE_HEURISTIC = "stated heuristic (no trained artifact loaded)"


@dataclass
class Signal:
    """One risk input.  ``value is None`` means genuinely unavailable."""
    name: str
    value: float | int | str | None
    unit: str
    source: str
    detail: str = ""

    @property
    def display(self) -> str:
        if self.value is None:
            return "Unavailable"
        if isinstance(self.value, float):
            return f"{self.value:.3f}{(' ' + self.unit) if self.unit else ''}"
        return f"{self.value}{(' ' + self.unit) if self.unit else ''}"


# ---------------------------------------------------------------------------
# QKD anomaly signal
# ---------------------------------------------------------------------------
class QKDAnomalySource:
    """Trained QKDAnomalyDetector when exported, else a stated QBER heuristic.

    The heuristic is:  score = clip(QBER_upper_bound / QBER_abort_threshold, 0, 1)

    It is monotone in the *decision* quantity the protocol already uses, it is
    reproducible, and it is NOT a probability and NOT a trained-model output.
    Because it is not a probability, the notebook's cost-derived probability
    thresholds do not apply to it - the dashboard uses a separate, stated band
    set with it (see AppConfig.heuristic_*).
    """

    def __init__(self, artifact_path: str, abort_threshold: float):
        self.artifact_path = artifact_path
        self.abort_threshold = float(abort_threshold)
        self.detector = None
        self.status = ""
        self.trained = False
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(self.artifact_path):
            self.status = (f"No trained QKD anomaly-detector artifact at "
                           f"{self.artifact_path}. Using the stated observed-QBER "
                           f"heuristic instead.")
            return
        try:
            import joblib
            obj = joblib.load(self.artifact_path)
        except Exception as exc:
            self.status = (f"Artifact present but could not be loaded "
                           f"({type(exc).__name__}: {exc}). Using the stated "
                           f"observed-QBER heuristic instead.")
            return
        cols = list(getattr(obj, "FEATURE_COLS", []))
        if cols != list(nr.FEATURE_COLS):
            self.status = (f"Artifact feature schema does not match the framework "
                           f"contract. Expected {list(nr.FEATURE_COLS)}, artifact "
                           f"has {cols}. Refusing to score. Using the stated "
                           f"observed-QBER heuristic instead.")
            return
        if not getattr(obj, "trained", False):
            self.status = ("Artifact loaded but is not marked trained. Refusing to "
                           "score. Using the stated observed-QBER heuristic instead.")
            return
        self.detector = obj
        self.trained = True
        self.status = f"Trained QKD anomaly detector loaded from {self.artifact_path}."

    @property
    def source(self) -> str:
        return SOURCE_TRAINED if self.trained else SOURCE_HEURISTIC

    def score(self, feature_row: dict[str, Any], qber_upper: float | None) -> Signal:
        if self.trained:
            try:
                v = float(self.detector.predict_proba(feature_row))
            except Exception as exc:
                return Signal("QKD anomaly score", None, "",
                              self.source, f"scoring failed: {exc}")
            return Signal("QKD anomaly score", v, "", self.source,
                          "trained ensemble probability of an attacked session")
        if qber_upper is None:
            return Signal("QKD anomaly score", None, "", self.source,
                          "no QBER upper bound available for this session")
        v = float(np.clip(qber_upper / max(1e-9, self.abort_threshold), 0.0, 1.0))
        return Signal("QKD anomaly score", v, "", self.source,
                      f"QBER upper bound {qber_upper:.4f} / abort threshold "
                      f"{self.abort_threshold:.4f}, clipped to [0,1]. "
                      f"Not a probability.")


# ---------------------------------------------------------------------------
# Network threat signal (recorded replay through the strict NIDS gate)
# ---------------------------------------------------------------------------
REQUIRED_NIDS_FILES = ("nids_inference_bundle.joblib", "nids_run_metadata.json",
                       "nids_artifact_manifest.json", "network_feature_pool.csv")


class NetworkThreatSource:
    """Strict NIDS gate + recorded feature replay.

    The adapter class is the notebook's own ``NIDSThreatAdapter`` - schema
    fingerprint, feature order, calibrator monotonicity, deployability,
    reliability and artifact SHA-256 are all checked there.  If any check fails
    the score is ``None`` and the mode is QKD-only.  No zero-filled feature
    vector is ever submitted.

    The replayed rows come from ``network_feature_pool.csv``, which is IoT-23
    derived network telemetry recorded during NIDS training.  It is labelled
    "Recorded network telemetry replay" everywhere it is shown and was **not**
    captured from the Alice/Bob message demonstration in this dashboard.
    """

    def __init__(self, artifacts_dir: str):
        self.dir = artifacts_dir
        self.adapter = None
        self.pool = None
        self.status = NET_MISSING
        self.reasons: list[str] = []
        self.cursor = 0
        self._load()

    def _load(self) -> None:
        if not os.path.isdir(self.dir):
            self.reasons = [f"artifact directory not found: {self.dir}"]
            self.status = NET_MISSING
            return
        missing = [f for f in REQUIRED_NIDS_FILES
                   if not os.path.isfile(os.path.join(self.dir, f))]
        if missing:
            self.reasons = [f"missing artifact file: {m}" for m in missing]
            self.status = NET_MISSING
            return
        try:
            self.adapter = nr.load_nids_adapter(self.dir)
        except Exception as exc:
            self.reasons = [f"adapter could not be constructed "
                            f"({type(exc).__name__}: {exc})"]
            self.status = NET_INCOMPATIBLE
            return
        self.reasons = list(self.adapter.reasons)
        if not self.adapter.reliable:
            self.status = NET_REJECTED
            return
        try:
            self.pool = nr.pd.read_csv(os.path.join(self.dir, "network_feature_pool.csv"))
        except Exception as exc:
            self.reasons = [f"feature pool unreadable ({type(exc).__name__}: {exc})"]
            self.status = NET_INCOMPATIBLE
            return
        missing_cols = [c for c in nr.EXPECTED_NIDS_FEATURES
                        if c not in self.pool.columns]
        if missing_cols:
            self.reasons = [f"feature pool is missing contract columns: {missing_cols}"]
            self.status = NET_INCOMPATIBLE
            self.pool = None
            return
        self.status = NET_AVAILABLE

    @property
    def available(self) -> bool:
        return self.status == NET_AVAILABLE

    def next_row(self) -> Signal:
        if not self.available or self.pool is None or len(self.pool) == 0:
            return Signal("Network risk probability", None, "",
                          "recorded network telemetry replay (unavailable)",
                          "; ".join(self.reasons) or "no NIDS artifacts loaded")
        row = self.pool.iloc[self.cursor % len(self.pool)]
        self.cursor += 1
        features = {c: float(row[c]) for c in nr.EXPECTED_NIDS_FEATURES}
        try:
            result = self.adapter.infer(features)[0]
        except Exception as exc:
            return Signal("Network risk probability", None, "",
                          "recorded network telemetry replay",
                          f"inference failed: {type(exc).__name__}: {exc}")
        if result.get("threat_score") is None:
            return Signal("Network risk probability", None, "",
                          "recorded network telemetry replay",
                          result.get("refusal", "; ".join(self.adapter.reasons)))
        return Signal("Network risk probability", float(result["threat_score"]), "",
                      "recorded network telemetry replay (IoT-23 derived flow "
                      "features from the NIDS export; NOT captured from this "
                      "dashboard's Alice/Bob demonstration)",
                      f"flow row {self.cursor - 1} of {len(self.pool)}, "
                      f"operating threshold {result.get('threshold')}")


# ---------------------------------------------------------------------------
# Pool demand / depletion
# ---------------------------------------------------------------------------
class DepletionSource:
    """Trained PoolDemandForecaster when exported, else a linear trend."""

    def __init__(self, artifact_path: str, trend_window: int, floor_bits: int):
        self.artifact_path = artifact_path
        self.trend_window = int(trend_window)
        self.floor_bits = int(floor_bits)
        self.forecaster = None
        self.status = ""
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(self.artifact_path):
            self.status = (f"No fitted pool-demand forecaster at "
                           f"{self.artifact_path}. Using a linear trend over the "
                           f"last {self.trend_window} observed pool readings.")
            return
        try:
            import joblib
            self.forecaster = joblib.load(self.artifact_path)
            self.status = f"Fitted PoolDemandForecaster loaded from {self.artifact_path}."
        except Exception as exc:
            self.status = (f"Forecaster artifact present but could not be loaded "
                           f"({type(exc).__name__}: {exc}). Using a linear trend "
                           f"instead.")

    @property
    def source(self) -> str:
        return SOURCE_TRAINED if self.forecaster is not None else SOURCE_HEURISTIC

    def estimate(self, pool_df) -> tuple[Signal, float | None]:
        """Returns (signal, numeric sessions-to-depletion or None)."""
        if pool_df is None or len(pool_df) < 3:
            return (Signal("Sessions to pool depletion", None, "sessions",
                           self.source, "fewer than 3 pool readings so far"), None)
        if self.forecaster is not None:
            try:
                ttd = self.forecaster.predict_time_to_depletion(pool_df)
            except Exception as exc:
                return (Signal("Sessions to pool depletion", None, "sessions",
                               self.source, f"forecast failed: {exc}"), None)
            num = None if isinstance(ttd, str) else int(ttd)
            return (Signal("Sessions to pool depletion",
                           ttd if isinstance(ttd, str) else int(ttd),
                           "" if isinstance(ttd, str) else "sessions",
                           self.source, "fitted forecaster"), num)

        y = (pool_df.sort_values("session_id")["total_available_bits"]
             .astype(float).values[-self.trend_window:])
        slope = float(np.polyfit(np.arange(len(y)), y, 1)[0])
        current = float(y[-1])
        if slope >= 0:
            return (Signal("Sessions to pool depletion",
                           f"not reached (pool trend {slope:+.0f} bits/session)", "",
                           self.source,
                           f"least-squares slope over the last {len(y)} readings"),
                    None)
        sessions = max(0.0, (current - self.floor_bits) / (-slope))
        return (Signal("Sessions to pool depletion", int(np.floor(sessions)), "sessions",
                       self.source,
                       f"({current:.0f} available - {self.floor_bits} reserve floor) "
                       f"/ {abs(slope):.0f} bits per session, least-squares slope "
                       f"over the last {len(y)} readings"),
                float(sessions))


# ---------------------------------------------------------------------------
# Fusion
# ---------------------------------------------------------------------------
@dataclass
class FusionResult:
    fused_score: float | None
    mode: str
    explanation: str
    inputs: list[Signal] = field(default_factory=list)


class FusionSource:
    """Combines the QKD and network signals - or states that it cannot.

    Step 7C's fitted fusion model is not exported by the notebook, so unless a
    weights file is supplied the dashboard runs in QKD-only mode and says so.
    It never invents a weighting.
    """

    def __init__(self, weights_path: str):
        self.weights_path = weights_path
        self.weights: dict[str, Any] | None = None
        self.status = ""
        if os.path.isfile(weights_path):
            try:
                with open(weights_path) as fh:
                    w = json.load(fh)
                if not (0.0 <= float(w.get("w_qkd", -1)) <= 1.0):
                    raise ValueError("w_qkd must be in [0,1]")
                self.weights = w
                self.status = f"Fusion weights loaded from {weights_path}."
            except Exception as exc:
                self.status = (f"Fusion weights present but invalid "
                               f"({type(exc).__name__}: {exc}). Running QKD-only.")
        else:
            self.status = ("Fusion weights were not exported by the research "
                           "notebook (Step 7C fits them in-run). Running QKD-only: "
                           "the fused score IS the QKD anomaly score, and the "
                           "network signal is shown as a separate input only.")

    def fuse(self, qkd: Signal, net: Signal) -> FusionResult:
        if qkd.value is None:
            return FusionResult(None, "UNAVAILABLE",
                                "No QKD anomaly score for this session.", [qkd, net])
        if self.weights is None or net.value is None:
            why = ("fusion weights not exported" if self.weights is None
                   else "network signal unavailable")
            return FusionResult(float(qkd.value), nr.NIDS_FALLBACK_MODE,
                                f"QKD-only ({why}); fused score = QKD anomaly score.",
                                [qkd, net])
        w = float(self.weights["w_qkd"])
        fused = w * float(qkd.value) + (1.0 - w) * float(net.value)
        return FusionResult(fused, nr.NIDS_RELIABLE_MODE,
                            f"w_qkd={w:.2f} x QKD {qkd.value:.3f} + "
                            f"{1 - w:.2f} x network {net.value:.3f}", [qkd, net])
