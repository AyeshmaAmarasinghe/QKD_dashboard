"""Real framework smoke test - NOT a deterministic fixture test.

This runs the actual simulated BB84 protocol (Qiskit Aer, one circuit per
photon), admits the resulting bits to the real key pool, delivers a real
AES-256-GCM message with them and checks that a tampered copy is rejected.  It
is the one test that evidences the end-to-end claim; everything it touches is
the framework's own code.

Marked ``slow``: run with ``pytest -m slow``.
"""
from __future__ import annotations

import pytest

from dashboard.adapter import SessionParams
from dashboard.runtime import secure_messaging as sm

pytestmark = pytest.mark.slow

CLEAN = SessionParams(n_bits=1500, error_rate=0.01, eve_rate=0.0,
                      sample_fraction=0.25, seed=42)
ATTACKED = SessionParams(n_bits=1500, error_rate=0.01, eve_rate=0.5,
                         sample_fraction=0.25, seed=42)


def test_bb84_to_key_to_aes_gcm_end_to_end(adapter):
    out = adapter.run_session(CLEAN)
    assert out.accepted, f"clean session aborted: {out.reason}"
    assert out.final_secret_bits > 0
    assert adapter.key_pool.get_pool_status()["total_available_bits"] > 0

    rec = adapter.send_secure("End-to-end message over BB84-derived key material.")
    assert rec.outcome == sm.OUT_DELIVERED
    assert rec.detail == "End-to-end message over BB84-derived key material."

    bad = adapter.send_secure("This one is altered in transit.", tamper="ciphertext")
    assert bad.outcome == sm.OUT_INTEGRITY_FAILURE


def test_eve_changes_the_channel_and_the_material_is_rejected(adapter):
    clean = adapter.run_session(CLEAN)
    assert clean.accepted
    bits_after_clean = adapter.key_pool.get_pool_status()["total_available_bits"]

    attacked = adapter.run_session(ATTACKED)
    assert not attacked.accepted, (
        "a 50% intercept-resend eavesdropper must push the QBER upper bound "
        "above the abort threshold")
    assert attacked.qber_point > clean.qber_point, (
        "the eavesdropper must change the actual simulated channel, not just a "
        "displayed score")
    assert attacked.admitted_bits == 0
    assert attacked.decision["action"] == "REKEY_NOW"


def test_replenishment_under_a_persistent_eavesdropper_cannot_manufacture_key(adapter):
    """Rekeying does not remove an eavesdropper: with Eve left on, every
    replenishment session must abort and the pool must not grow."""
    adapter.channel = ATTACKED
    before = adapter.key_pool.get_pool_status()["total_available_bits"]
    added = adapter._replenish(target_bits=512)
    after = adapter.key_pool.get_pool_status()["total_available_bits"]
    assert added == 0
    assert after == before
    assert all(a["eve_rate"] == ATTACKED.eve_rate
               for a in adapter.replenish_log)
