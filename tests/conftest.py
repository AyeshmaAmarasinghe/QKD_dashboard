"""Fixtures.

Two clearly separated kinds of test live in this suite:

* **Deterministic fixture tests** (most of them) build the runtime, then inject
  key material directly into the pool so that policy, lifecycle and crypto
  behaviour can be exercised without paying for a BB84 run.  They never assert
  anything about QKD physics.
* **Real framework smoke tests** (``test_smoke_real_bb84.py``) run the actual
  simulated BB84 protocol end to end.  They are marked ``slow``.
"""
from __future__ import annotations

import numpy as np
import pytest

from dashboard.adapter import FrameworkAdapter, SessionParams
from dashboard.config import load_config
from dashboard.runtime import notebook_runtime as nr
from dashboard.runtime.secure_messaging import NonceLedger


@pytest.fixture
def cfg():
    c = load_config()
    # Point every optional artifact at a path that does not exist, so the tests
    # exercise the documented "unavailable" paths rather than whatever happens
    # to be installed on the machine running them.
    c.nids_artifacts_dir = "/nonexistent/nids"
    c.qkd_detector_artifact = "/nonexistent/detector.joblib"
    c.pool_forecaster_artifact = "/nonexistent/forecaster.joblib"
    c.fusion_weights_artifact = "/nonexistent/fusion.json"
    return c


@pytest.fixture
def adapter(cfg):
    return FrameworkAdapter(cfg, NonceLedger())


@pytest.fixture
def stocked(adapter):
    """An adapter whose pool holds deterministic key material and whose
    replenishment is disabled, so pool-scarcity behaviour is reproducible."""
    stock_pool(adapter, bits=2048)
    disable_replenishment(adapter)
    return adapter


def stock_pool(adapter: FrameworkAdapter, bits: int = 2048, seed: int = 11) -> str:
    """Inject deterministic 'secure' key material straight into the pool.

    This bypasses BB84 on purpose: these are fixture bits, not a QKD result, and
    no test that uses them makes a claim about QKD.
    """
    rng = np.random.default_rng(seed)
    return adapter.key_pool.store_key(rng.integers(0, 2, bits).astype(np.uint8),
                                      session_id="fixture", secure=True)


def disable_replenishment(adapter: FrameworkAdapter) -> None:
    adapter.lifecycle._replenish_fn = lambda target_bits, session_id=None: 0
    adapter.lifecycle.max_retries = 0


def feed_telemetry(adapter: FrameworkAdapter, rows) -> None:
    """Push synthetic per-session telemetry through the real exporters.

    ``rows`` is a sequence of (qber_point, qber_upper, secure) triples.
    """
    for i, (q, qu, secure) in enumerate(rows, start=1):
        adapter.qber_exporter.log(
            session_id=i, qber=q, secure=secure, eve_intercept_rate=0.0,
            channel_time_sec=0.002, n_bits_sent=2000,
            qber_detail={"qber_upper": qu, "qber_sample_size": 250,
                         "qber_errors": int(q * 250), "qber_sifted_len": 1000,
                         "qber_sample_fraction": 0.25, "qber_ci_width": qu - q,
                         "qber_decision_basis": "upper_bound",
                         "final_key_len": 400 if secure else 0})
        adapter.pool_exporter.log(session_id=i, key_pool=adapter.key_pool)
