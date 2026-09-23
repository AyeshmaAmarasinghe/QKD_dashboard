"""Page 1 - Overview: current state of the QKD link and the AI control plane."""
from __future__ import annotations

import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard import theme
from dashboard.adapter import FrameworkAdapter
from dashboard.runtime import risk as risk_mod

ARCH = [
    ("BB84 / post-processing", "Simulated BB84, sifting, QBER bound, Cascade, "
                               "verification, privacy amplification"),
    ("KMS", "Key pool, atomic reservation, lifecycle states"),
    ("AI control", "Risk inputs, fusion, decision engine"),
    ("Rekey execution", "Activate / revoke / expire / destroy"),
    ("Secure application", "AES-256-GCM Alice/Bob demonstration"),
]


def render(adapter: FrameworkAdapter) -> None:
    cfg = adapter.cfg
    st.subheader("System overview and health")
    st.caption("Values below come from this session's runtime. Anything the "
               "framework cannot produce is shown as Unavailable, never as zero.")

    last = adapter.sessions[-1] if adapter.sessions else None
    # Read-only: the decision was computed when the session was run. Redrawing
    # this page must never issue a rekey or consume a key.
    decision = adapter.last_decision
    pool = adapter.key_pool_summary()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        if last is None or last.qber_point is None:
            theme.card("Observed QBER", "Unavailable", sub="No session has been run yet.")
        else:
            nominal = cfg.qber_nominal_warning
            if last.qber_upper is not None and last.qber_upper > cfg.qber_abort_threshold:
                status = "ABORTED"
            elif nominal is not None and last.qber_point > nominal:
                status = "ABOVE NOMINAL"
            else:
                status = "ACCEPTED"
            theme.card(
                "Observed QBER", f"{last.qber_point * 100:.2f}", "%",
                badge_text=status,
                sub=(f"{cfg.qber_confidence:.0%} one-sided upper bound "
                     f"{last.qber_upper * 100:.2f}% vs {cfg.qber_abort_threshold:.0%} "
                     f"abort threshold. The abort decision uses the bound, not the "
                     f"point estimate."
                     + (f" Optional nominal watch line: {nominal:.1%} (not a "
                        f"security threshold)." if nominal is not None else "")))
    with c2:
        theme.card("Available secret bits", f"{pool['available_secret_bits']:,}", "bits",
                   sub=(f"Funds {pool['fundable_operational_keys']} operational key(s) "
                        f"of {cfg.operational_key_bits} bits. Reserve floor "
                        f"{pool['reserve_floor_bits']:,} bits "
                        f"({pool['reserve_level_pct']:.0f}% of floor). "
                        f"Pool occupancy is bits held; key utilisation "
                        f"({pool['key_utilisation_pct']:.1f}%) is bits consumed "
                        f"over bits generated - different quantities."))
    with c3:
        if not decision.get("available"):
            theme.card("Fused risk score", "Unavailable",
                       sub=decision.get("why", ""))
        else:
            theme.card("Fused risk score", f"{decision['fused_score']:.3f}", "/ 1.0",
                       badge_text=decision["fusion_mode"].replace("_", " "),
                       sub=decision["fusion_explanation"])
    with c4:
        if not decision.get("available"):
            theme.card("AI decision", "Unavailable", sub=decision.get("why", ""),
                       small=True)
        else:
            outcome = decision["execution_outcome"]
            short = {"REKEYED": "REKEYED", "NO_ACTION": "NO ACTION",
                     "ALERT_RAISED_NO_REKEY": "ALERT RAISED",
                     "FAILED_NO_KEY_AVAILABLE": "FAILED - NO KEY",
                     "DEFERRED_KEY_SCARCITY": "DEFERRED"}.get(
                         outcome, "ARMED" if outcome.startswith("ARMED") else outcome)
            theme.card("AI decision", decision["action"],
                       badge_text=short,
                       small=True,
                       sub=(f"{decision['reason']}. Execution outcome: "
                            f"{decision['execution_outcome']}."))

    # ---------------- decision explanation -------------------------------
    if decision.get("available"):
        left, right = st.columns([3, 2])
        with left:
            interval = decision["recommended_interval_sessions"]
            due = decision.get("scheduled_rekey_due_session")
            st.markdown(
                f'<div class="qkd-note"><b>Why this decision.</b> '
                f'Fused risk {decision["fused_score"]:.3f} sits in the '
                f'<b>{decision["action"]}</b> band '
                f'(watch &ge; {decision["bands"]["watch"]:.3f}, '
                f'alert &ge; {decision["bands"]["alert"]:.3f}, '
                f'immediate &ge; {decision["bands"]["high"]:.3f}); '
                f'{theme.esc(decision["reason"])}. Recommended rekey interval: '
                f'<b>{interval} session(s)</b>'
                + (f'; a rekey is armed for session {due}.' if due else '.')
                + f'<br><span style="font-size:.8rem">Band provenance: '
                  f'{theme.esc(decision["band_provenance"])}</span></div>',
                unsafe_allow_html=True)
        with right:
            if decision["key_changed"]:
                theme.note(f"The control plane changed the active key for "
                           f"{cfg.connection_id} to "
                           f"{str(decision['active_key_id'])[:8]}. The Alice/Bob "
                           f"demonstration uses this same connection, so its next "
                           f"message is protected by the new key.")
            else:
                theme.note("No key change was executed for this session.")

    # ---------------- architecture strip ---------------------------------
    st.markdown("#### Architecture")
    cols = st.columns(len(ARCH))
    for i, (col, (name, detail)) in enumerate(zip(cols, ARCH), start=1):
        with col:
            theme.stage_card(i, name, "READY", detail)

    # ---------------- charts + status ------------------------------------
    st.write("")
    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Recent QBER history")
        _qber_chart(adapter)
    with right:
        st.markdown("##### Component readiness")
        status = adapter.system_status()
        st.dataframe(pd.DataFrame(status["components"]), hide_index=True,
                     use_container_width=True,
                     column_config={"component": st.column_config.TextColumn(width="medium"),
                                    "status": st.column_config.TextColumn(width="small"),
                                    "detail": st.column_config.TextColumn(width="large")})

    st.markdown("##### Recent decision and lifecycle events")
    st.dataframe(adapter.recent_events(cfg.history_rows), hide_index=True,
                 use_container_width=True)

    # ---------------- risk inputs panel ----------------------------------
    with st.expander("AI control-plane inputs (actual values and their provenance)"):
        _inputs_panel(adapter, decision)

    with st.expander("Network model status"):
        _network_panel(adapter)

    with st.expander("Saved baseline / evaluation summary (read-only)"):
        _baseline_panel(adapter)

    with st.expander("Run summary, configuration and source mapping"):
        summary = adapter.run_summary()
        st.json({k: v for k, v in summary.items()
                 if k not in ("configuration", "source_cell_map")}, expanded=False)
        st.markdown("**Configuration**")
        st.dataframe(pd.DataFrame(summary["configuration"]), hide_index=True,
                     use_container_width=True, height=260)
        st.markdown("**Notebook source-cell mapping**")
        st.dataframe(pd.DataFrame([
            {"module": k, "notebook cell": v["notebook_cell_index"],
             "provides": v["provides"]}
            for k, v in summary["source_cell_map"].items()]),
            hide_index=True, use_container_width=True, height=300)
        st.download_button("Download sanitised run export (JSON)",
                           data=adapter.export_events(),
                           file_name="qkd_dashboard_run_export.json",
                           mime="application/json")
        st.caption("The export carries key ids, lengths, states, timestamps, "
                   "decisions and outcomes only. No secret key material and no "
                   "message plaintext is written to it.")


def _qber_chart(adapter: FrameworkAdapter) -> None:
    cfg = adapter.cfg
    df = adapter.telemetry_snapshot(cfg.history_rows)
    if df.empty:
        theme.note("No sessions yet. Run one on the QKD Session Monitor page.")
        return
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df["session_id"], y=df["qber_observed"] * 100,
                             mode="lines+markers", name="Observed QBER",
                             line=dict(color=theme.BLUE, width=2)))
    if df["qber_upper_bound"].notna().any():
        fig.add_trace(go.Scatter(x=df["session_id"], y=df["qber_upper_bound"] * 100,
                                 mode="lines+markers", name=f"{cfg.qber_confidence:.0%} upper bound",
                                 line=dict(color="#7c3aed", width=1.5, dash="dot")))
    fig.add_hline(y=cfg.qber_abort_threshold * 100, line_color="#dc2626",
                  line_dash="dash",
                  annotation_text=f"abort threshold {cfg.qber_abort_threshold:.0%}",
                  annotation_position="top left")
    if cfg.qber_nominal_warning is not None:
        fig.add_hline(y=cfg.qber_nominal_warning * 100, line_color="#d97706",
                      line_dash="dot",
                      annotation_text=f"nominal watch {cfg.qber_nominal_warning:.1%} "
                                      f"(not a security threshold)",
                      annotation_position="bottom left")
    fig.update_layout(height=330, margin=dict(l=8, r=8, t=10, b=8),
                      paper_bgcolor="white", plot_bgcolor="white",
                      yaxis_title="QBER (%)", xaxis_title="Session",
                      legend=dict(orientation="h", y=-0.25))
    st.plotly_chart(fig, use_container_width=True)


def _inputs_panel(adapter: FrameworkAdapter, decision: dict) -> None:
    rows = []
    for sig in decision.get("signals", []):
        rows.append({"input": sig.name, "value": sig.display,
                     "source": sig.source, "detail": sig.detail})
    pool = adapter.key_pool_summary()
    rows.append({"input": "Pool state - available secret bits",
                 "value": f"{pool['available_secret_bits']:,} bits",
                 "source": "live key pool", "detail": "bits free to allocate"})
    rows.append({"input": "Pool state - fundable operational keys",
                 "value": str(pool["fundable_operational_keys"]),
                 "source": "live key pool",
                 "detail": f"available bits // {adapter.cfg.operational_key_bits}"})
    if not rows:
        theme.note("No inputs yet - run a session first.")
        return
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.markdown("**Policy thresholds in use**")
    b = decision.get("bands") or {"watch": adapter.policy_bands[0],
                                  "alert": adapter.policy_bands[1],
                                  "high": adapter.policy_bands[2]}
    st.dataframe(pd.DataFrame([
        {"threshold": "watch (ALERT_ONLY floor)", "value": f"{b['watch']:.3f}"},
        {"threshold": "alert (SCHEDULE_REKEY floor)", "value": f"{b['alert']:.3f}"},
        {"threshold": "high (REKEY_NOW floor)", "value": f"{b['high']:.3f}"},
        {"threshold": "pool depletion forcing REKEY_NOW",
         "value": f"{adapter.cfg.depletion_urgent_sessions} session(s)"},
        {"threshold": "QBER abort threshold",
         "value": f"{adapter.cfg.qber_abort_threshold:.3f} "
                  f"(decided on the {adapter.cfg.qber_confidence:.0%} upper bound)"},
    ]), hide_index=True, use_container_width=True)
    st.caption(adapter.threshold_provenance)


def _network_panel(adapter: FrameworkAdapter) -> None:
    src = adapter.net_source
    names = {risk_mod.NET_AVAILABLE: "Available and enabled",
             risk_mod.NET_MISSING: "Missing",
             risk_mod.NET_INCOMPATIBLE: "Incompatible",
             risk_mod.NET_REJECTED: "Rejected by the reliability gate"}
    st.markdown(f"**Status:** {theme.badge(names.get(src.status, src.status))}",
                unsafe_allow_html=True)
    if src.status != risk_mod.NET_AVAILABLE:
        theme.note("QKD-only fallback is in force: the network contribution is "
                   "not used, and no network risk value is invented. The "
                   "framework's documented QKD-only path is what runs.", warn=True)
    st.write(f"Artifact directory configured as `{adapter.cfg.nids_artifacts_dir}`.")
    if src.reasons:
        st.markdown("**Reasons reported by the strict NIDS gate:**")
        for r in src.reasons:
            st.write(f"- {r}")
    if src.available:
        st.write(f"Recorded network telemetry replay: {len(src.pool):,} flow "
                 f"feature rows, cursor at {src.cursor}.")
        theme.note("These rows are IoT-23 derived flow features recorded during "
                   "NIDS training. They were NOT captured from this dashboard's "
                   "Alice/Bob message demonstration.")


def _baseline_panel(adapter: FrameworkAdapter) -> None:
    path = adapter.cfg.baseline_summary_artifact
    if not os.path.isfile(path):
        theme.note(f"No saved baseline summary at {path}. Nothing is computed "
                   f"here: this panel only displays a file the research "
                   f"notebook already produced.")
        return
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        theme.note(f"Baseline summary present but unreadable: {exc}", warn=True)
        return
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.caption(f"Read from {path}. No experiment is launched by this dashboard.")
