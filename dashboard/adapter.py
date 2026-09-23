"""The one adapter between the Streamlit UI and the research framework.

The UI never touches ``notebook_runtime`` directly; it calls this object.  One
instance is held in ``st.session_state`` for the whole browser session, so
navigation and widget reruns do not rebuild the key pool, restart the lifecycle
manager or re-run a QKD session.

Control-plane integration (deliberate, and the point of the exercise): the key
pool, the lifecycle manager, the key-delivery API, the rekeying command
interface and the application secure channel all share ONE runtime and ONE
connection id.  An AI-issued rekey therefore changes the key the Alice/Bob
demonstration actually uses.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from dashboard.config import AppConfig, config_report
from dashboard.runtime import notebook_runtime as nr
from dashboard.runtime import risk as risk_mod
from dashboard.runtime import secure_messaging as sm

READY = "READY"
DEGRADED = "DEGRADED"
UNAVAILABLE = "UNAVAILABLE"


@dataclass
class SessionParams:
    n_bits: int
    error_rate: float
    eve_rate: float
    sample_fraction: float
    seed: int

    def validate(self, cfg: AppConfig) -> list[str]:
        errs = []
        if not (cfg.session_size_min <= self.n_bits <= cfg.session_size_max):
            errs.append(f"session size must be between {cfg.session_size_min} and "
                        f"{cfg.session_size_max} photons")
        if not (cfg.noise_min <= self.error_rate <= cfg.noise_max):
            errs.append(f"channel depolarising probability must be between "
                        f"{cfg.noise_min} and {cfg.noise_max}")
        if not (cfg.eve_min <= self.eve_rate <= cfg.eve_max):
            errs.append("configured interception rate must be between 0 and 1")
        if not (cfg.sample_fraction_min <= self.sample_fraction <= cfg.sample_fraction_max):
            errs.append(f"QBER sample fraction must be between "
                        f"{cfg.sample_fraction_min} and {cfg.sample_fraction_max}")
        if self.seed < 0:
            errs.append("seed must be non-negative")
        return errs


@dataclass
class SessionOutcome:
    session_id: int
    accepted: bool
    reason: str
    qber_point: float | None
    qber_upper: float | None
    confidence: float | None
    sifted_bits: int | None
    sample_bits: int | None
    sample_errors: int | None
    final_secret_bits: int
    admitted_bits: int
    auth_topup_bits: int
    channel_time_sec: float
    wall_time_sec: float
    params: dict[str, Any]
    stages: list[dict[str, str]] = field(default_factory=list)
    decision: dict[str, Any] | None = None


# Abort reasons as the runtime reports them, mapped to readable text.
ABORT_REASONS = {
    "qber_above_threshold": "QBER upper confidence bound above the abort threshold",
    "authentication_failed": "classical-channel authentication failed",
    "key_verification_failed": "key verification failed (reconciled keys differ)",
    "empty_after_privacy_amplification":
        "privacy amplification left no extractable secret bits",
    "ok": "accepted",
}


class FrameworkAdapter:
    # ------------------------------------------------------------------
    def __init__(self, cfg: AppConfig, nonce_ledger: sm.NonceLedger):
        self.cfg = cfg
        self.nonce_ledger = nonce_ledger
        self.started_at = time.time()
        self.reset(hard=False)

    # ------------------------------------------------------------------
    # construction / reset
    # ------------------------------------------------------------------
    def reset(self, hard: bool = True) -> None:
        """Rebuild the whole simulation runtime.

        The nonce ledger is NOT cleared: a reset must not make a previously used
        (key, nonce) pair look fresh.  Old key material is destroyed with the old
        pool object; no key survives a reset.
        """
        cfg = self.cfg
        self.rng = nr.make_rng(cfg.seed_default)
        self.auth_reserve = nr.AuthKeyReserve(rng=nr.make_rng(cfg.seed_default))
        self.auth_channel = nr.AuthenticatedClassicalChannel(
            self.auth_reserve, rng=nr.make_rng(cfg.seed_default))

        self.key_pool = nr.KeyPool(max_age_sec=None)
        self.metrics = nr.BB84Metrics()
        self.qber_exporter = nr.QBERStreamExporter()
        self.pool_exporter = nr.PoolLevelExporter()

        # Channel conditions are STATE, not per-call arguments: replenishment
        # runs over the same channel the operator configured, so Eve is never
        # silently switched off to make key generation succeed.
        self.channel = SessionParams(
            n_bits=cfg.session_size_default, error_rate=cfg.noise_default,
            eve_rate=cfg.eve_default, sample_fraction=cfg.sample_fraction_default,
            seed=cfg.seed_default)
        self.replenish_log: list[dict[str, Any]] = []

        self.lifecycle = nr.KeyLifecycleManager(
            self.key_pool, key_length=cfg.operational_key_bits,
            key_ttl_sec=cfg.key_ttl_sec,
            replenish_fn=self._replenish, max_retries=cfg.replenish_max_retries,
            generate_sessions=cfg.replenish_sessions, rng=self.rng,
            seed=cfg.seed_default, min_reserve_keys=cfg.min_reserve_keys)
        self.api = nr.QKDKeyDeliveryAPI(self.lifecycle,
                                        default_key_length=cfg.operational_key_bits)
        self.api.open_connection(cfg.connection_id, "alice", "bob")

        self.messaging = sm.SecureMessagingService(
            self.api, self.lifecycle, cfg.connection_id, self.nonce_ledger,
            key_bits=cfg.operational_key_bits,
            max_messages_per_key=cfg.max_messages_per_key,
            max_message_bytes=cfg.max_message_bytes)

        # ---- AI control plane ----
        self.qkd_source = risk_mod.QKDAnomalySource(cfg.qkd_detector_artifact,
                                                    cfg.qber_abort_threshold)
        self.net_source = risk_mod.NetworkThreatSource(cfg.nids_artifacts_dir)
        self.depletion_source = risk_mod.DepletionSource(
            cfg.pool_forecaster_artifact, cfg.depletion_trend_window,
            floor_bits=cfg.operational_key_bits)
        self.fusion = risk_mod.FusionSource(cfg.fusion_weights_artifact)

        if self.qkd_source.trained:
            bands = (cfg.trained_watch, cfg.trained_alert, cfg.trained_high)
            self.threshold_provenance = (
                "cost-derived probability thresholds from the research notebook "
                "(cell 74), applicable because a trained detector is loaded")
        else:
            bands = (cfg.heuristic_watch, cfg.heuristic_alert, cfg.heuristic_high)
            self.threshold_provenance = (
                "stated heuristic bands on (QBER upper bound / QBER abort "
                "threshold). The notebook's cost-derived probability thresholds "
                "are NOT reused here: the heuristic score is not a probability.")
        self.policy_bands = bands
        self.decision_engine = nr.DecisionEngine(
            anomaly_threshold_watch=bands[0], anomaly_threshold_alert=bands[1],
            anomaly_threshold_high=bands[2],
            depletion_urgent_sessions=cfg.depletion_urgent_sessions)
        self.scheduler = nr.AdaptiveScheduler()
        # budget_aware=False: the key-budget governor scales the rekey bar by the
        # shortfall over a FIXED replay window. This dashboard is open-ended, so
        # there is no meaningful "sessions remaining" and the governor would be
        # inert anyway. Scarcity here surfaces as POOL_EXHAUSTED / blocked state.
        self.rekeying = nr.RekeyingCommandInterface(
            self.key_pool, key_length=cfg.operational_key_bits,
            budget_aware=False, lifecycle=self.lifecycle,
            connection_id=cfg.connection_id, key_ttl_sec=cfg.key_ttl_sec)

        self.sessions: list[SessionOutcome] = []
        #: Result of the most recent control-plane evaluation.  Computed ONLY
        #: when a session is run - never on a redraw - so navigating or pressing
        #: "Refresh display" cannot issue a rekey or consume a key.
        self.last_decision: dict[str, Any] = {
            "available": False, "why": "no QKD sessions have been run yet"}
        self._next_session_id = 1
        self.events: list[dict[str, Any]] = []
        self._log_event("SIMULATION_RESET" if hard else "SIMULATION_START",
                        "runtime constructed; key pool empty")

    # ------------------------------------------------------------------
    def _log_event(self, kind: str, detail: str, **extra) -> None:
        self.events.append({"at": time.time(), "event": kind, "detail": detail,
                            **extra})

    # ------------------------------------------------------------------
    # bounded, channel-preserving replenishment
    # ------------------------------------------------------------------
    def _replenish(self, target_bits: int, session_id=None) -> int:
        """Generate new BB84 material under the CURRENTLY CONFIGURED channel.

        Replaces ``KeyLifecycleManager._default_replenish``, which draws a random
        noise level and hard-codes ``eve_rate=0.0``.  Silently removing the
        eavesdropper during replenishment would let the system "recover" from an
        attack that is still in progress.  Bounded by ``generate_sessions``;
        aborted sessions contribute nothing because ``KeyPool.store_key`` refuses
        insecure material.
        """
        added = 0
        attempts = []
        for k in range(self.lifecycle.generate_sessions):
            if added >= target_bits:
                break
            out = self._run_one_session(
                SessionParams(n_bits=self.channel.n_bits,
                              error_rate=self.channel.error_rate,
                              eve_rate=self.channel.eve_rate,
                              sample_fraction=self.channel.sample_fraction,
                              seed=self.channel.seed),
                origin="replenishment")
            attempts.append({"session_id": out.session_id, "accepted": out.accepted,
                             "reason": out.reason, "bits": out.admitted_bits})
            added += out.admitted_bits
        self.replenish_log.append(
            {"at": time.time(), "target_bits": int(target_bits),
             "added_bits": int(added), "attempts": attempts,
             "eve_rate": self.channel.eve_rate,
             "error_rate": self.channel.error_rate})
        self._log_event("REPLENISH_ATTEMPT",
                        f"target {int(target_bits)} bits, added {int(added)} bits "
                        f"under configured interception {self.channel.eve_rate:.0%} "
                        f"and noise {self.channel.error_rate:.2%}")
        return int(added)

    # ------------------------------------------------------------------
    # QKD session execution
    # ------------------------------------------------------------------
    def _run_one_session(self, p: SessionParams, origin: str) -> SessionOutcome:
        sid = self._next_session_id
        self._next_session_id += 1
        detail: dict[str, Any] = {}
        t0 = time.time()
        bits_before = self.key_pool.get_pool_status()["total_available_bits"]
        key, qber, secure, ctime, reason = nr.run_monitored_session(
            session_id=sid, n_bits=p.n_bits, error_rate=p.error_rate,
            eve_rate=p.eve_rate, key_pool=self.key_pool, metrics=self.metrics,
            qber_exporter=self.qber_exporter, pool_exporter=self.pool_exporter,
            rng=self.rng, auth_channel=self.auth_channel,
            auth_reserve=self.auth_reserve)
        wall = time.time() - t0
        bits_after = self.key_pool.get_pool_status()["total_available_bits"]

        # run_monitored_session does not thread qber_detail back out; recover the
        # per-session detail from the exporter record it just wrote.
        rec = self.qber_exporter.records[-1] if self.qber_exporter.records else {}

        stages = self._stage_list(secure, reason, rec, bits_after - bits_before)
        out = SessionOutcome(
            session_id=sid, accepted=bool(secure),
            reason=ABORT_REASONS.get(reason, reason),
            qber_point=float(qber) if rec else None,
            qber_upper=_f(rec.get("qber_upper")),
            confidence=self.cfg.qber_confidence,
            sifted_bits=_i(rec.get("qber_sifted_len")),
            sample_bits=_i(rec.get("qber_sample_size")),
            sample_errors=_i(rec.get("qber_errors")),
            final_secret_bits=int(rec.get("final_key_len") or 0),
            admitted_bits=int(max(0, bits_after - bits_before)),
            auth_topup_bits=int(rec.get("auth_reserve_topup") or 0)
            if "auth_reserve_topup" in rec else 0,
            channel_time_sec=float(ctime), wall_time_sec=wall,
            params={**asdict(p), "origin": origin}, stages=stages)
        self.sessions.append(out)
        self._log_event("QKD_SESSION",
                        f"session {sid} ({origin}): "
                        f"{'accepted' if secure else 'aborted'} - {out.reason}",
                        session_id=sid, accepted=bool(secure),
                        qber_point=out.qber_point, qber_upper=out.qber_upper,
                        secret_bits=out.final_secret_bits)
        return out

    def _stage_list(self, secure: bool, reason: str, rec: dict,
                    admitted: int) -> list[dict[str, str]]:
        """Protocol stages, reporting ACTUAL completion - never animated."""
        def done(ok, note=""):
            return {"state": "complete" if ok else "not reached", "note": note}

        reached_qber = rec.get("qber_sample_size") is not None
        passed_qber = secure or reason not in ("qber_above_threshold",)
        ec_done = rec.get("ec_parity_disclosed") is not None
        verified = secure or reason == "empty_after_privacy_amplification"
        pa_done = bool(rec.get("final_key_len"))
        stages = [
            ("Alice preparation", done(True, f"{rec.get('n_bits_sent', '?')} photons encoded")),
            ("Quantum transmission", done(True, "depolarising channel"
                                                + (f" + configured interception "
                                                   f"{rec.get('eve_intercept_rate', 0):.0%}"
                                                   if rec.get("eve_intercept_rate") else ""))),
            ("Bob measurement", done(True, "random basis per photon")),
            ("Sifting", done(reached_qber,
                             f"{rec.get('qber_sifted_len', '?')} sifted bits")),
            ("QBER estimation", done(reached_qber,
                                     f"{rec.get('qber_errors', '?')}/"
                                     f"{rec.get('qber_sample_size', '?')} sampled bits "
                                     f"in error")),
            ("Reconciliation", done(ec_done and passed_qber,
                                    f"{rec.get('ec_parity_disclosed', '-')} parity bits "
                                    f"disclosed" if ec_done else "")),
            ("Key verification", done(verified and ec_done,
                                      f"{rec.get('verify_tag_bits', '-')}-bit tag"
                                      if ec_done else "")),
            ("Privacy amplification", done(pa_done,
                                           f"{rec.get('final_key_len', 0)} secret bits"
                                           if pa_done else
                                           "no extractable secret bits")),
            ("Admission to key pool", done(admitted > 0,
                                           f"{admitted} bits admitted" if admitted > 0
                                           else "nothing admitted")),
        ]
        return [{"stage": n, **s} for n, s in stages]

    # ------------------------------------------------------------------
    def run_session(self, p: SessionParams) -> SessionOutcome:
        """Public entry point: run one operator-initiated session, then evaluate
        the AI control plane over it and act on the decision."""
        errs = p.validate(self.cfg)
        if errs:
            raise ValueError("; ".join(errs))
        self.channel = p                      # channel conditions persist
        out = self._run_one_session(p, origin="operator")
        out.decision = self.evaluate_decision(out)
        self.last_decision = out.decision
        return out

    # ------------------------------------------------------------------
    # AI decision evaluation
    # ------------------------------------------------------------------
    def feature_frame(self) -> pd.DataFrame | None:
        if not self.qber_exporter.records:
            return None
        try:
            df, _ = nr.extract_features(self.qber_exporter.to_dataframe(),
                                        self.pool_exporter.to_dataframe())
        except Exception:
            return None
        return df

    def evaluate_decision(self, out: SessionOutcome | None = None) -> dict[str, Any]:
        """Score the latest session, decide, and ACT on the decision.

        This mutates the control plane (it can issue a rekey), so it is called
        exactly once per executed QKD session - never from a view.
        """
        df = self.feature_frame()
        if df is None or df.empty:
            return {"available": False,
                    "why": "no QKD sessions have been run yet"}
        row = df.iloc[-1]
        feat = {c: float(row[c]) for c in nr.FEATURE_COLS}

        qkd_sig = self.qkd_source.score(feat, _f(row.get("qber_upper")))
        net_sig = self.net_source.next_row()
        fused = self.fusion.fuse(qkd_sig, net_sig)

        pool_df = self.pool_exporter.to_dataframe()
        ttd_sig, ttd_num = self.depletion_source.estimate(pool_df)
        ttd_for_engine = ttd_num if ttd_num is not None else "not reached"

        if fused.fused_score is None:
            return {"available": False, "why": fused.explanation,
                    "signals": [qkd_sig, net_sig, ttd_sig]}

        interval = self.scheduler.recommend_interval(fused.fused_score, ttd_for_engine)
        sid = int(row["session_id"])
        decision = self.decision_engine.decide(sid, float(fused.fused_score),
                                               ttd_for_engine, int(interval))
        before = self.lifecycle.active_by_conn.get(self.cfg.connection_id)
        self.rekeying.handle_decision(decision, sid)
        after = self.lifecycle.active_by_conn.get(self.cfg.connection_id)
        if after is not None and after != before:
            self._register_control_plane_key(after)
        events = [e for e in self.rekeying.event_log if e["session_id"] == sid]
        outcome = events[-1]["outcome"] if events else "NO_ACTION"

        if after != before:
            self._log_event("CONTROL_PLANE_REKEY",
                            f"session {sid}: active key for {self.cfg.connection_id} "
                            f"changed to {str(after)[:8]}", session_id=sid)
        self._log_event("AI_DECISION",
                        f"session {sid}: {decision['action']} - {decision['reason']} "
                        f"(outcome {outcome})", session_id=sid,
                        action=decision["action"], fused_score=fused.fused_score)

        return {
            "available": True,
            "session_id": sid,
            "action": decision["action"],
            "reason": decision["reason"],
            "fused_score": float(fused.fused_score),
            "fusion_mode": fused.mode,
            "fusion_explanation": fused.explanation,
            "recommended_interval_sessions": int(interval),
            "scheduled_rekey_due_session": self.rekeying.pending_schedule,
            "execution_outcome": outcome,
            "key_changed": after != before,
            "active_key_id": after,
            "signals": [qkd_sig, net_sig, ttd_sig],
            "pool_bits": int(row["pool_available_bits"]),
            "bands": {"watch": self.policy_bands[0], "alert": self.policy_bands[1],
                      "high": self.policy_bands[2]},
            "band_provenance": self.threshold_provenance,
        }

    def _register_control_plane_key(self, key_id: str) -> None:
        """Make a control-plane-issued key retrievable through the delivery API.

        RekeyingCommandInterface calls KeyLifecycleManager.rekey() directly, so
        the ETSI-style delivery API never sees the resulting key_id and the
        responder's ``get_key_with_key_id`` would refuse it - the AI rekey would
        change the sender's key and silently break the receiver.  Registering the
        id on the same connection is the integration fix; it grants no new
        capability, because the key already exists on that connection.
        """
        self.api._index[(self.cfg.connection_id, key_id)] = key_id

    # ------------------------------------------------------------------
    # snapshots for the UI
    # ------------------------------------------------------------------
    def system_status(self) -> dict[str, Any]:
        cfg = self.cfg
        pool = self.key_pool.get_pool_status()
        aead = _aead_available()
        comps = [
            {"component": "Simulated BB84 engine (Qiskit Aer)",
             "status": READY, "detail": f"{nr.QBERCalculator.SECURITY_THRESHOLD:.0%} "
                                        f"abort threshold, "
                                        f"{cfg.qber_confidence:.0%} one-sided bound"},
            {"component": "Classical-channel authentication (Wegman-Carter)",
             "status": READY if self.auth_reserve.available() > 0 else DEGRADED,
             "detail": f"{self.auth_reserve.available()} reserve bits "
                       f"({self.auth_reserve.bootstrap_bits} pre-shared at start)"},
            {"component": "Key pool / KMS",
             "status": READY if pool["total_available_bits"] > 0 else DEGRADED,
             "detail": f"{pool['total_available_bits']} bits available"},
            {"component": "Key lifecycle manager",
             "status": UNAVAILABLE if self.lifecycle.communication_blocked else READY,
             "detail": ("communication BLOCKED - no acceptable key material"
                        if self.lifecycle.communication_blocked
                        else f"{len(self.lifecycle.keys)} key records tracked")},
            {"component": "Application AEAD (cryptography AESGCM)",
             "status": READY if aead else UNAVAILABLE,
             "detail": (f"{self.messaging.algorithm}" if aead
                        else "the `cryptography` package is not installed")},
            {"component": "QKD anomaly signal",
             "status": READY if self.qkd_source.trained else DEGRADED,
             "detail": self.qkd_source.status},
            {"component": "Network threat model (NIDS)",
             "status": READY if self.net_source.available else UNAVAILABLE,
             "detail": self.network_status_text()},
            {"component": "Pool demand forecast",
             "status": READY if self.depletion_source.forecaster is not None else DEGRADED,
             "detail": self.depletion_source.status},
            {"component": "Risk fusion",
             "status": READY if self.fusion.weights else DEGRADED,
             "detail": self.fusion.status},
        ]
        return {"components": comps,
                "protocol": cfg.protocol_label,
                "provenance": cfg.provenance_label,
                "sessions_run": len(self.sessions),
                "uptime_sec": time.time() - self.started_at}

    def network_status_text(self) -> str:
        s = self.net_source.status
        names = {risk_mod.NET_AVAILABLE: "Available and enabled",
                 risk_mod.NET_MISSING: "Missing",
                 risk_mod.NET_INCOMPATIBLE: "Incompatible",
                 risk_mod.NET_REJECTED: "Rejected by the reliability gate"}
        head = names.get(s, s)
        if s != risk_mod.NET_AVAILABLE:
            head += " - QKD-only fallback"
        reasons = "; ".join(self.net_source.reasons[:4])
        return f"{head}. {reasons}" if reasons else head

    def telemetry_snapshot(self, limit: int | None = None) -> pd.DataFrame:
        rows = [{
            "session_id": s.session_id,
            "origin": s.params.get("origin"),
            "qber_observed": s.qber_point,
            "qber_upper_bound": s.qber_upper,
            "sifted_bits": s.sifted_bits,
            "sample_bits": s.sample_bits,
            "sample_errors": s.sample_errors,
            "secret_bits": s.final_secret_bits,
            "admitted_bits": s.admitted_bits,
            "status": "ACCEPTED" if s.accepted else "ABORTED",
            "reason": s.reason,
            "configured_interception": s.params.get("eve_rate"),
            "configured_noise": s.params.get("error_rate"),
        } for s in self.sessions]
        df = pd.DataFrame(rows)
        if limit and len(df) > limit:
            df = df.tail(limit)
        return df

    def key_pool_summary(self) -> dict[str, Any]:
        pool = self.key_pool.get_pool_status()
        kms = self.key_pool.kms_metrics()
        life_states = self.lifecycle.state_counts()
        active = sum(1 for r in self.lifecycle.keys.values()
                     if r["state"] == nr.KeyLifecycleManager.ACTIVE)
        reserve_bits = self.lifecycle.min_reserve_bits
        return {
            "available_secret_bits": pool["total_available_bits"],
            "fundable_operational_keys": pool["fundable_operational_keys"],
            "active_operational_keys": active,
            # Definitions are spelled out in the UI; keep the names unambiguous.
            "pool_records_consumed": self.key_pool.status_counts().get(nr.KeyStatus.CONSUMED, 0),
            "pool_records_expired": self.key_pool.status_counts().get(nr.KeyStatus.EXPIRED, 0),
            "pool_records_destroyed": self.key_pool.status_counts().get(nr.KeyStatus.DESTROYED, 0),
            "operational_keys_revoked": life_states.get(nr.KeyLifecycleManager.REVOKED, 0),
            "operational_keys_expired": life_states.get(nr.KeyLifecycleManager.EXPIRED, 0),
            "operational_keys_destroyed": life_states.get(nr.KeyLifecycleManager.DESTROYED, 0),
            "reserve_floor_bits": reserve_bits,
            "reserve_level_pct": (100.0 * pool["total_available_bits"] / reserve_bits
                                  if reserve_bits else float("nan")),
            "key_utilisation_pct": kms["key_utilization_%"],
            "expired_unused_bits": kms["expired_unused_bits"],
            "destroyed_bits": kms["destroyed_bits"],
            "underflow_events": kms["pool_underflow_events"],
            "communication_blocked": self.lifecycle.communication_blocked,
            "status_counts": self.key_pool.status_counts(),
        }

    def pool_history(self) -> pd.DataFrame:
        if not self.pool_exporter.records:
            return pd.DataFrame(columns=["session_id", "total_available_bits"])
        return self.pool_exporter.to_dataframe()[
            ["session_id", "total_available_bits", "available_keys"]]

    def key_records(self) -> pd.DataFrame:
        """Non-secret key descriptors only.  Raw key material never appears."""
        rows = []
        for r in self.key_pool.pool:
            rows.append({
                "key_id": _short_id(r["key_id"]),
                "scope": "pool record",
                "connection": r["connection_id"] or "-",
                "session_id": r["session_id"],
                "length_bits": r["total_bits"],
                "remaining_bits": len(r["remaining"]),
                "status": r["status"],
                "created": _ts(r["created_at"]),
                "expires": _ts(r["expires_at"]),
            })
        for kid, r in self.lifecycle.keys.items():
            rows.append({
                "key_id": _short_id(kid),
                "scope": "operational key",
                "connection": r["connection_id"],
                "session_id": r["session_id"],
                "length_bits": r["length_bits"],
                "remaining_bits": "-",
                "status": r["state"],
                "created": _ts(r["created_at"]),
                "expires": _ts(r["expires_at"]),
            })
        return pd.DataFrame(rows)

    def lifecycle_records(self, limit: int = 50) -> pd.DataFrame:
        df = self.lifecycle.audit_dataframe()
        if df.empty:
            return pd.DataFrame(columns=["time", "operation", "key_id",
                                         "connection_id", "detail"])
        df = df.copy()
        df["time"] = df["timestamp"].map(_ts)
        # Audit rows for pool-level operations carry no key_id; pandas turns the
        # resulting column into floats with NaN, so shorten defensively.
        df["key_id"] = df["key_id"].map(_short_id)
        return df[["time", "operation", "key_id", "connection_id",
                   "session_id", "detail"]].tail(limit).iloc[::-1]

    def recent_events(self, limit: int = 25) -> pd.DataFrame:
        rows = [{"time": _ts(e["at"]), "event": e["event"], "detail": e["detail"]}
                for e in self.events[-limit:]][::-1]
        return pd.DataFrame(rows)

    # ------------------------------------------------------------------
    # secure messaging
    # ------------------------------------------------------------------
    def send_secure(self, text: str, tamper: str = "none") -> sm.MessageRecord:
        return self.messaging.send_and_receive(text, tamper=tamper)

    def replay_last(self) -> sm.MessageRecord | None:
        delivered = [m for m in self.messaging.messages
                     if m.outcome == sm.OUT_DELIVERED and m.key_id != "-"]
        if not delivered:
            return None
        return self.messaging.send_and_receive("", replay_of=delivered[-1].seq)

    # ------------------------------------------------------------------
    # export
    # ------------------------------------------------------------------
    def run_summary(self) -> dict[str, Any]:
        import platform
        import sys
        versions = {}
        for mod in ("numpy", "pandas", "scipy", "scikit-learn", "qiskit",
                    "qiskit-aer", "cryptography", "streamlit", "plotly", "joblib"):
            try:
                from importlib.metadata import version
                versions[mod] = version(mod)
            except Exception:
                versions[mod] = "not installed"
        return {
            "generated_at": _ts(time.time()),
            "provenance": self.cfg.provenance_label,
            "protocol": self.cfg.protocol_label,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "dependency_versions": versions,
            "notebook_source": nr.NOTEBOOK_SOURCE,
            "notebook_sha256": nr.NOTEBOOK_SHA256,
            "source_cell_map": nr.SOURCE_CELL_MAP,
            "configuration": config_report(self.cfg),
            "data_provenance": {
                "qkd_telemetry": "generated by this dashboard's simulated BB84 runs",
                "network_telemetry": ("recorded IoT-23 derived flow-feature replay "
                                      "from the NIDS export"
                                      if self.net_source.available
                                      else "unavailable"),
                "qkd_anomaly_signal": self.qkd_source.status,
                "pool_demand_signal": self.depletion_source.status,
                "fusion": self.fusion.status,
            },
            "session_count": len(self.sessions),
            "messaging_summary": self.messaging.summary(),
            "key_pool_summary": self.key_pool_summary(),
        }

    def export_events(self) -> str:
        """Sanitised audit export.  Contains NO key material - only key ids,
        lengths, states, timestamps, decisions and outcomes."""
        payload = {
            "run_summary": self.run_summary(),
            "sessions": [self._sanitised_session(s) for s in self.sessions],
            "decisions": (self.decision_engine.to_dataframe().to_dict("records")
                          if self.decision_engine.decision_log else []),
            "rekeying_events": self.rekeying.event_log,
            "lifecycle_audit": self.lifecycle.audit_log,
            "messages": [{"seq": m.seq, "key_id": m.key_id[:8],
                          "outcome": m.outcome,
                          "plaintext_bytes": m.plaintext_len,
                          "ciphertext_bytes": m.ciphertext_len,
                          "rekey_trigger": m.rekey_trigger,
                          "at": _ts(m.at)} for m in self.messaging.messages],
            "events": self.events,
            "replenishment": self.replenish_log,
        }
        return json.dumps(_scrub(payload), indent=2, default=str)

    @staticmethod
    def _sanitised_session(s: SessionOutcome) -> dict[str, Any]:
        d = asdict(s)
        d.pop("stages", None)
        return d


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
_FORBIDDEN_KEYS = {"key", "key_bits", "material", "bits", "remaining",
                   "ciphertext", "nonce", "plaintext", "aad", "detail_plaintext"}


def _scrub(obj):
    """Belt-and-braces: drop anything that could carry raw key or plaintext."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k in _FORBIDDEN_KEYS else _scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return "<redacted>"
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    return obj


def _aead_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except Exception:
        return False


def _f(v):
    try:
        return None if v is None or (isinstance(v, float) and np.isnan(v)) else float(v)
    except Exception:
        return None


def _i(v):
    try:
        return None if v is None else int(v)
    except Exception:
        return None


def _short_id(value) -> str:
    """8-character display id, tolerant of None and pandas NaN."""
    if value is None:
        return "-"
    if isinstance(value, float) and np.isnan(value):
        return "-"
    return str(value)[:8]


def _ts(t):
    if t is None:
        return "-"
    return time.strftime("%H:%M:%S", time.localtime(float(t)))
