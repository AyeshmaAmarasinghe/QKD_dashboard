"""Control-plane integration and key-pool policy: §14 items 9-15 and 17."""
from __future__ import annotations

import numpy as np
import pytest

from dashboard.adapter import SessionParams
from dashboard.runtime import notebook_runtime as nr
from dashboard.runtime import risk as risk_mod
from dashboard.runtime import secure_messaging as sm
from tests.conftest import disable_replenishment, feed_telemetry, stock_pool


def test_ai_rekey_changes_the_channels_effective_key(stocked):
    first = stocked.send_secure("before the rekey")
    assert first.outcome == sm.OUT_DELIVERED
    before = first.key_id

    # The control plane rekeys the SAME connection the application uses.
    result = stocked.lifecycle.rekey(connection_id=stocked.cfg.connection_id,
                                     session_id=999)
    assert result["ok"], result
    stocked._register_control_plane_key(result["key_id"])
    assert result["key_id"] != before

    after = stocked.send_secure("after the rekey")
    assert after.outcome == sm.OUT_DELIVERED
    assert after.key_id == result["key_id"], (
        "an AI rekey must change the key the communication demo actually uses")


def test_empty_pool_gives_controlled_blocking(adapter):
    disable_replenishment(adapter)            # no key material anywhere
    rec = adapter.send_secure("this cannot be protected")
    assert rec.outcome in (sm.OUT_EMPTY_POOL, sm.OUT_PENDING_KEY)
    assert adapter.lifecycle.communication_blocked
    assert adapter.key_pool_summary()["communication_blocked"] is True


def test_replenishment_preserves_configured_eve_and_noise(adapter):
    """The notebook's default replenishment hard-codes eve_rate=0.0.  The
    dashboard's replenisher must use the channel the operator configured."""
    seen = []
    orig = nr.run_monitored_session

    def spy(**kw):
        seen.append((kw["eve_rate"], kw["error_rate"]))
        return None, 0.5, False, 0.001, "qber_above_threshold"

    nr.run_monitored_session = spy
    try:
        adapter.channel = SessionParams(2000, 0.04, 0.35, 0.25, 42)
        added = adapter._replenish(target_bits=512)
    finally:
        nr.run_monitored_session = orig

    assert seen, "replenishment must actually attempt sessions"
    assert all(e == 0.35 and n == 0.04 for e, n in seen), (
        f"replenishment ran under {seen}, not the configured channel")
    assert added == 0, "aborted sessions must contribute no bits"
    assert len(seen) <= adapter.lifecycle.generate_sessions, "retries must be bounded"


def test_aborted_material_never_enters_the_pool(adapter):
    with pytest.raises(ValueError) as exc:
        adapter.key_pool.store_key(np.ones(256, dtype=np.uint8),
                                   session_id=1, secure=False)
    assert "insecure" in str(exc.value).lower()
    assert adapter.key_pool.get_pool_status()["total_available_bits"] == 0


def test_missing_nids_gives_explicit_qkd_only_fallback(adapter):
    src = adapter.net_source
    assert src.status == risk_mod.NET_MISSING
    assert not src.available
    sig = src.next_row()
    assert sig.value is None, "a missing model must not produce a score"
    assert "QKD-only" in adapter.network_status_text()

    stock_pool(adapter, 2048)
    feed_telemetry(adapter, [(0.02, 0.04, True), (0.02, 0.045, True),
                             (0.02, 0.05, True)])
    decision = adapter.evaluate_decision()
    assert decision["available"]
    assert decision["fusion_mode"] == nr.NIDS_FALLBACK_MODE
    assert decision["fused_score"] == pytest.approx(
        [s for s in decision["signals"] if s.name.startswith("QKD")][0].value)


def test_invalid_nids_schema_fails_visibly(adapter, tmp_path):
    """A bundle that exists but does not match the contract must be refused with
    a reason, not silently scored."""
    d = tmp_path / "nids"
    d.mkdir()
    import joblib
    joblib.dump({"bundle_format": "wrong", "feature_columns": ["a", "b"]},
                d / "nids_inference_bundle.joblib")
    (d / "nids_run_metadata.json").write_text("{}")
    (d / "nids_artifact_manifest.json").write_text("{}")
    (d / "network_feature_pool.csv").write_text("a,b\n1,2\n")

    src = risk_mod.NetworkThreatSource(str(d))
    assert src.status == risk_mod.NET_REJECTED
    assert src.reasons, "the gate must say why it refused the artifact"
    assert src.next_row().value is None


def test_missing_detector_uses_labelled_heuristic_not_a_fake_score(adapter):
    assert not adapter.qkd_source.trained
    sig = adapter.qkd_source.score({}, qber_upper=0.055)
    assert sig.value == pytest.approx(0.5, abs=0.01)
    assert "heuristic" in sig.source
    assert "Not a probability" in sig.detail
    # And with no QBER at all it is unavailable, not zero.
    assert adapter.qkd_source.score({}, qber_upper=None).value is None


def test_thresholds_match_the_score_scale_in_use(adapter):
    assert adapter.policy_bands == (adapter.cfg.heuristic_watch,
                                    adapter.cfg.heuristic_alert,
                                    adapter.cfg.heuristic_high)
    assert "not a probability" in adapter.threshold_provenance.lower()


def test_reset_does_not_revive_old_keys(stocked):
    rec = stocked.send_secure("pre-reset")
    old_key_id = rec.key_id
    old_records = set(stocked.lifecycle.keys)
    stocked.reset()
    assert stocked.lifecycle.keys == {}
    assert stocked.key_pool.get_pool_status()["total_available_bits"] == 0
    assert stocked.messaging.messages == []
    assert old_key_id not in stocked.lifecycle.keys
    assert old_records                       # the fixture really had keys


def test_statuses_and_metrics_come_from_the_backend(stocked):
    stock_pool(stocked, 512, seed=3)
    summary = stocked.key_pool_summary()
    assert summary["available_secret_bits"] == \
        stocked.key_pool.get_pool_status()["total_available_bits"]
    assert summary["fundable_operational_keys"] == \
        summary["available_secret_bits"] // stocked.cfg.operational_key_bits
    status = stocked.system_status()
    names = {c["component"]: c["status"] for c in status["components"]}
    assert names["Network threat model (NIDS)"] == "UNAVAILABLE"
    assert names["QKD anomaly signal"] == "DEGRADED"


def test_depletion_estimate_is_unavailable_without_history(adapter):
    sig, num = adapter.depletion_source.estimate(adapter.pool_exporter.to_dataframe()
                                                 if adapter.pool_exporter.records else None)
    assert sig.value is None and num is None


def test_rekey_triggers_are_distinguished(stocked):
    for i in range(stocked.cfg.max_messages_per_key + 1):
        stocked.send_secure(f"message {i}")
    triggers = stocked.messaging.summary()["rekeys_by_trigger"]
    assert triggers.get(sm.TRIGGER_INITIAL) == 1
    assert triggers.get(sm.TRIGGER_USAGE, 0) >= 1, (
        "a usage-limit rotation must be labelled as such, not as a threat response")
    assert sm.TRIGGER_THREAT not in triggers
