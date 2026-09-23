"""Extract import-safe runtime definitions from the research notebook.

This script reads ``main-model-18-09-2026.ipynb`` and writes
``dashboard/runtime/notebook_runtime.py``.  It copies the *definition* part of
selected code cells VERBATIM and drops everything the notebook runs for its own
sake: demonstration runs, training loops, dataset loading, multi-seed
experiments, pip installs and display calls.

Nothing is executed from the notebook.  Each extracted block is truncated at an
explicit marker (``stop``) that was chosen by reading the cell, so the generated
module contains class/function definitions and module-level constants only.

Run it from the project root:

    python tools/extract_runtime.py --notebook ../main-model-18-09-2026.ipynb

The generated file is committed, so the dashboard does not need the notebook at
runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

# (cell index, short name, what it provides, start marker or None, stop marker or None)
# `start` / `stop` are literal line prefixes taken from the cell source.
CELLS = [
    (6, "config", "SEED, make_rng, crypto_rng, AUTH_*, OPERATIONAL_KEY_BITS, "
                  "KEY_MIN_BITS, KEY_TTL_SEC, BB84_SESSION_SIZES, EPS_*, "
                  "default_usage_policy", None,
     "print('Libraries loaded successfully."),
    (8, "alice", "Alice", None, "# Quick smoke test"),
    (10, "channel", "QuantumChannel (depolarising noise, Eve intercept-resend, loss)", None, None),
    (12, "bob", "Bob", None, None),
    (14, "sifting", "BB84KeySifting", None, None),
    (16, "auth", "AuthenticationError, AuthKeyReserve, toeplitz_tag, "
                 "AuthenticatedClassicalChannel", None,
     "# --- Demo: the rejection path actually fires"),
    (18, "qber", "QBERCalculator (point estimate + one-sided upper bound)", None,
     "print(f'QBERCalculator ready"),
    (20, "ec", "ErrorCorrection (Cascade with look-back)", None, None),
    (22, "verify", "key_verification_tag, keys_agree", None,
     "print(f'Key verification:"),
    (24, "pa", "PrivacyAmplification (Toeplitz universal hashing)", None, None),
    (26, "kms", "KeyStatus, KeyPool, SynchronizedKeyStores, BB84Metrics", None,
     "print(f'KeyPool ready"),
    (30, "session", "run_bb84_simulation", None, "# --- Demonstration run ---"),
    (32, "lifecycle", "KeyLifecycleManager", None, "print('KeyLifecycleManager ready"),
    (34, "delivery", "KeyDeliveryError, QKDKeyDeliveryAPI", None,
     "# --- Demo: full application-facing exchange"),
    (36, "secure_channel", "KeyReuseViolation, QKDSecureChannel (AES-GCM base class)", None,
     "# --- Demonstration: real traffic"),
    (52, "exporters", "QBERStreamExporter, PoolLevelExporter", None,
     "print('QBERStreamExporter"),
    (54, "monitored", "run_monitored_session", None, "print('run_monitored_session ready')"),
    (56, "features", "FEATURE_COLS, LABEL_COL, extract_features", None,
     "print('extract_features ready"),
    (60, "detector", "BaseAnomalyDetector, QKDAnomalyDetector, temporal_split "
                     "(definitions only - no training)", None,
     "train_df, val_df, test_df = temporal_split("),
    (66, "nids_adapter", "NIDSFeatureError, NIDSThreatAdapter, "
                         "GatedNetworkThreatDetector, load_nids_adapter "
                         "(strict gate only - Kaggle path discovery and the "
                         "legacy loader are NOT extracted)",
     "# Step 4B-STRICT: NIDS threat-score adapter",
     "NIDS_ADAPTER = load_nids_adapter("),
    (68, "forecaster", "PoolDemandForecaster (definition only - not fitted here)", None,
     "forecaster = PoolDemandForecaster(lookback=5)"),
    (70, "scheduler", "AdaptiveScheduler", None, "scheduler = AdaptiveScheduler()"),
    (74, "decision", "DecisionEngine + cost-derived thresholds "
                     "(anomaly_threshold_watch/alert/high)", None,
     "decision_engine = DecisionEngine("),
    (93, "rekeying", "RekeyingCommandInterface", None,
     "# Fix (2026-08-21, pool exhaustion): was RekeyingCommandInterface"),
    (95, "telemetry_logger", "SessionTelemetryLogger", None,
     "telemetry_logger = SessionTelemetryLogger("),
]

HEADER = '''"""GENERATED FILE - DO NOT EDIT BY HAND.

Runtime definitions extracted verbatim from the research notebook
``{nb}`` by ``tools/extract_runtime.py``.

Only class/function definitions and module-level constants are copied.  Every
demonstration run, training loop, dataset load, sweep, pip install and display
call in the notebook is excluded, so importing this module has no side effects
beyond defining names.

Source-cell mapping is printed below and is also available programmatically as
``SOURCE_CELL_MAP``.

Regenerate with::

    python tools/extract_runtime.py --notebook <path-to-notebook>
"""
# flake8: noqa
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import threading
import time
import uuid

import numpy as np
import pandas as pd

NOTEBOOK_SOURCE = {nb!r}
NOTEBOOK_SHA256 = {sha!r}
SOURCE_CELL_MAP = {cellmap!r}

# TensorFlow is optional in the notebook and is deliberately NOT a dependency of
# the dashboard: PoolDemandForecaster falls back to the scikit-learn MLP path.
try:  # pragma: no cover - environment dependent
    import tensorflow as _tf  # noqa: F401
    HAS_TENSORFLOW = True
except Exception:  # pragma: no cover
    HAS_TENSORFLOW = False

# The notebook prints status banners at module level.  Those are useful in a
# notebook and noise in a server process, so `print` is a no-op for the duration
# of the extracted block and is restored at the end of this file.  Because
# Python resolves globals at call time, methods that print when `verbose=True`
# are unaffected once it is restored.
_real_print = print


def print(*args, **kwargs):  # noqa: A001 - intentional, restored below
    return None


'''

FOOTER = '''

# Restore the real builtin for anything that prints at runtime.
print = _real_print
del _real_print
'''


def slice_cell(src: str, start: str | None, stop: str | None, cell_no: int) -> str:
    lines = src.splitlines()
    i0 = 0
    if start is not None:
        hits = [i for i, l in enumerate(lines) if l.startswith(start)]
        if not hits:
            raise SystemExit(f"cell {cell_no}: start marker not found: {start!r}")
        i0 = hits[0]
    i1 = len(lines)
    if stop is not None:
        hits = [i for i, l in enumerate(lines) if i > i0 and l.startswith(stop)]
        if not hits:
            raise SystemExit(f"cell {cell_no}: stop marker not found: {stop!r}")
        i1 = hits[0]
    return "\n".join(lines[i0:i1]).rstrip() + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--notebook", required=True)
    ap.add_argument("--out", default=os.path.join("dashboard", "runtime",
                                                  "notebook_runtime.py"))
    args = ap.parse_args()

    with open(args.notebook, "rb") as fh:
        raw = fh.read()
    sha = hashlib.sha256(raw).hexdigest()
    nb = json.loads(raw.decode("utf-8"))
    cells = nb["cells"]

    cellmap = {}
    chunks = []
    for idx, name, provides, start, stop in CELLS:
        cell = cells[idx]
        if cell["cell_type"] != "code":
            raise SystemExit(f"cell {idx} is not a code cell")
        body = slice_cell("".join(cell["source"]), start, stop, idx)
        cellmap[name] = {"notebook_cell_index": idx, "provides": provides}
        chunks.append(
            f"# ===================================================================\n"
            f"# notebook cell [{idx}] -> {name}\n"
            f"#   provides: {provides}\n"
            f"# ===================================================================\n"
            f"{body}\n"
        )

    out = HEADER.format(nb=os.path.basename(args.notebook), sha=sha,
                        cellmap=cellmap) + "\n".join(chunks) + FOOTER
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)
    import builtins; print_ = builtins.print
    print_(f"wrote {args.out} ({len(out.splitlines())} lines) "
           f"from {len(CELLS)} notebook cells; notebook sha256={sha[:16]}...")


if __name__ == "__main__":
    main()
