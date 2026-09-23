"""Single place for every configurable path, threshold and bound.

Nothing else in the dashboard hard-codes an artifact path, a security threshold
or a confidence level.  Values come, in order of precedence:

  1. environment variables  (``QKDDASH_<FIELD>``)
  2. ``dashboard_config.toml`` next to ``app.py``
  3. the defaults below, which are themselves read from the extracted notebook
     runtime wherever the notebook defines the quantity.

Paths default to the ``artifacts/`` directory beside ``app.py``; they may be
absolute.  No developer or Kaggle path appears anywhere.
"""
from __future__ import annotations

import os
#import tomllib
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "dashboard_config.toml"

# ---------------------------------------------------------------------------
# Defaults that are *derived from the notebook* are read at import time so the
# dashboard cannot drift from the framework it displays.
from dashboard.runtime import notebook_runtime as nr  # noqa: E402


@dataclass
class AppConfig:
    # --- artifact / data locations -------------------------------------
    #: Directory holding the NIDS export from ``nids-model-15-09-2026.ipynb``
    #: (nids_inference_bundle.joblib, nids_run_metadata.json,
    #:  nids_artifact_manifest.json, deployability.json,
    #:  network_feature_pool.csv).  Missing -> network signal UNAVAILABLE.
    nids_artifacts_dir: str = str(PROJECT_ROOT / "artifacts" / "nids")
    #: Optional joblib export of a trained QKDAnomalyDetector.  Missing ->
    #: the observed-QBER heuristic is used and labelled as such.
    qkd_detector_artifact: str = str(PROJECT_ROOT / "artifacts" / "qkd_anomaly_detector.joblib")
    #: Optional joblib export of a fitted PoolDemandForecaster.  Missing ->
    #: linear-trend depletion estimate, labelled as such.
    pool_forecaster_artifact: str = str(PROJECT_ROOT / "artifacts" / "pool_forecaster.joblib")
    #: Optional JSON of fusion weights exported from Step 7C.  Missing ->
    #: QKD-only fusion mode.
    fusion_weights_artifact: str = str(PROJECT_ROOT / "artifacts" / "fusion_weights.json")
    #: Optional saved baseline/evaluation summary (CSV or JSON) shown read-only.
    baseline_summary_artifact: str = str(PROJECT_ROOT / "artifacts" / "baseline_summary.csv")
    #: Optional design-preview fixtures.  Displayed ONLY in design-preview mode.
    design_fixture_file: str = str(PROJECT_ROOT / "artifacts" / "design_preview_fixtures.json")
    #: Where the sanitised audit export is written.
    export_dir: str = str(PROJECT_ROOT / "exports")

    # --- simulation bounds (UI validation) ------------------------------
    session_size_min: int = 200
    session_size_max: int = 6000
    #: 2000 photons, not the notebook's 1000-photon telemetry size. With a 25%
    #: sample of a ~500-bit sifted key the 99% upper confidence bound sits close
    #: to the 11% abort threshold even on a clean channel, so a smaller default
    #: would make every session look alarming for a purely statistical reason.
    session_size_default: int = 2000
    noise_min: float = 0.0
    noise_max: float = 0.15
    noise_default: float = 0.02
    eve_min: float = 0.0
    eve_max: float = 1.0
    eve_default: float = 0.0
    sample_fraction_min: float = 0.05
    sample_fraction_max: float = 0.50
    sample_fraction_default: float = 0.25
    seed_default: int = int(nr.SEED)

    # --- key management --------------------------------------------------
    operational_key_bits: int = int(nr.OPERATIONAL_KEY_BITS)
    key_min_bits: int = int(nr.KEY_MIN_BITS)
    key_ttl_sec: float = float(nr.KEY_TTL_SEC)
    connection_id: str = "alice<->bob"
    #: Reserve floor, in operational keys, used by KeyLifecycleManager.
    min_reserve_keys: int = 3
    #: Bounded replenishment: BB84 sessions per generate attempt, and retries.
    replenish_sessions: int = 3
    replenish_max_retries: int = 2

    # --- application messaging policy ------------------------------------
    #: Messages one operational key may protect before USAGE_LIMIT rotation.
    #: >1 so that an AI-triggered rotation is distinguishable from the
    #: per-message key allocation of a strict single-use policy.
    max_messages_per_key: int = 8
    max_message_bytes: int = 2048

    # --- decision policy --------------------------------------------------
    #: Thresholds used when a TRAINED QKD anomaly detector is loaded.  These
    #: are the notebook's cost-derived probability thresholds (cell 74).
    trained_watch: float = float(nr.anomaly_threshold_watch)
    trained_alert: float = float(nr.anomaly_threshold_alert)
    trained_high: float = float(nr.anomaly_threshold_high)
    #: Thresholds used with the observed-QBER heuristic.  The heuristic score is
    #: NOT a probability, so the cost-derived probability thresholds above do not
    #: apply to it.  These bands are STATED, not learned, and are expressed on
    #: the ratio (QBER upper bound / QBER abort threshold).
    heuristic_watch: float = 0.45
    heuristic_alert: float = 0.65
    heuristic_high: float = 0.85
    #: Pool depletion (in sessions) that forces REKEY_NOW.
    depletion_urgent_sessions: int = 2
    #: Window of past pool readings used by the linear-trend depletion estimate.
    depletion_trend_window: int = 8

    # --- QBER decision --------------------------------------------------
    #: Abort threshold and one-sided confidence, read from the notebook's
    #: QBERCalculator.  Displayed with their provenance; never re-typed from the
    #: prototype images.
    qber_abort_threshold: float = float(nr.QBERCalculator.SECURITY_THRESHOLD)
    qber_confidence: float = float(nr.QBERCalculator.DEFAULT_CONFIDENCE)
    #: OPTIONAL nominal/warning level.  This is an operational watch line only,
    #: NOT a security threshold and NOT an abort condition.  None disables it.
    qber_nominal_warning: float | None = 0.05

    # --- provenance strings ----------------------------------------------
    protocol_label: str = "Simulated BB84"
    provenance_label: str = "Research prototype - simulated QKD"

    # --- misc -------------------------------------------------------------
    #: Number of recent sessions charted / tabled.
    history_rows: int = 25
    design_preview: bool = False

    extra: dict[str, Any] = field(default_factory=dict)


def _coerce(value: Any, typ: Any) -> Any:
    if typ is bool or typ == "bool":
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if typ is int or typ == "int":
        return int(value)
    if typ is float or typ == "float":
        return float(value)
    return value


def load_config() -> AppConfig:
    data: dict[str, Any] = {}
    if CONFIG_FILE.is_file():
        with open(CONFIG_FILE, "rb") as fh:
            data.update(tomllib.load(fh))
    cfg = AppConfig()
    for f in fields(cfg):
        if f.name == "extra":
            continue
        raw = os.environ.get("QKDDASH_" + f.name.upper(), data.get(f.name))
        if raw is None:
            continue
        ann = f.type
        if f.name == "qber_nominal_warning":
            setattr(cfg, f.name, None if str(raw).lower() in ("", "none") else float(raw))
            continue
        setattr(cfg, f.name, _coerce(raw, ann))
    return cfg


def config_report(cfg: AppConfig) -> list[dict[str, str]]:
    """Non-secret configuration table for the run summary."""
    rows = []
    for f in fields(cfg):
        if f.name == "extra":
            continue
        val = getattr(cfg, f.name)
        rows.append({"setting": f.name, "value": str(val)})
    return rows
