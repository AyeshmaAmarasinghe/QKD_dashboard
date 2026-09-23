"""Page 3 - Key Pool and Lifecycle, plus the secure communication panel."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard import theme
from dashboard.adapter import FrameworkAdapter
from dashboard.runtime import secure_messaging as sm

OUTCOME_TEXT = {
    sm.OUT_DELIVERED: ("DELIVERED", "Authenticated and decrypted to the original text."),
    sm.OUT_INTEGRITY_FAILURE: ("INTEGRITY FAILURE",
                               "GCM authentication failed - the ciphertext or its "
                               "authenticated metadata was altered in transit."),
    sm.OUT_REPLAY_REJECTED: ("REPLAY REJECTED",
                             "A valid envelope was re-delivered. AES-GCM would have "
                             "accepted it; the replay ledger rejected it."),
    sm.OUT_INVALID_KEY: ("INVALID KEY", "The key is not ACTIVE, or has expired."),
    sm.OUT_PENDING_KEY: ("PENDING KEY GENERATION",
                         "No usable key yet; key generation was attempted and did "
                         "not yield acceptable material."),
    sm.OUT_EMPTY_POOL: ("BLOCKED - EMPTY POOL",
                        "The key pool cannot fund an operational key."),
    sm.OUT_REFUSED: ("REFUSED", "The request was refused before encryption."),
}


def render(adapter: FrameworkAdapter) -> None:
    cfg = adapter.cfg
    st.subheader("Key pool and lifecycle management")
    st.caption("Non-secret key descriptors only. Raw key material is never "
               "displayed, logged or exported.")

    pool = adapter.key_pool_summary()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        theme.card("Available secret bits", f"{pool['available_secret_bits']:,}", "bits",
                   sub=f"Pool bits free to allocate. Funds "
                       f"{pool['fundable_operational_keys']} operational key(s) of "
                       f"{cfg.operational_key_bits} bits. This is not the same as "
                       f"an AES key's length, nor the number of messages remaining.")
    with c2:
        theme.card("Active operational keys", f"{pool['active_operational_keys']}", "keys",
                   sub=f"Delivered keys currently in state ACTIVE on connection "
                       f"{cfg.connection_id}.")
    with c3:
        theme.card("Retired key records", f"{pool['pool_records_consumed']}", "consumed",
                   sub=(f"Pool records fully spent: {pool['pool_records_consumed']}; "
                        f"expired before use: {pool['pool_records_expired']}; "
                        f"zeroised: {pool['pool_records_destroyed']}. "
                        f"Operational keys revoked: {pool['operational_keys_revoked']}, "
                        f"expired: {pool['operational_keys_expired']}, "
                        f"destroyed: {pool['operational_keys_destroyed']}."))
    with c4:
        occ = pool["reserve_level_pct"]
        theme.card("Reserve level", f"{occ:.0f}", "% of floor",
                   badge_text="BLOCKED" if pool["communication_blocked"] else "AVAILABLE",
                   sub=(f"Reserve floor {pool['reserve_floor_bits']:,} bits "
                        f"({cfg.min_reserve_keys} operational keys). Key "
                        f"utilisation {pool['key_utilisation_pct']:.1f}% = bits "
                        f"consumed / bits generated - a different quantity from "
                        f"pool occupancy. Underflow events: "
                        f"{pool['underflow_events']}."))

    if pool["communication_blocked"]:
        theme.note("The key lifecycle manager is in BLOCK_COMMUNICATION state: "
                   "no acceptable key material is available and no key will be "
                   "issued. Recovery requires an acceptable new QKD session - "
                   "rekeying does not remove an eavesdropper.", warn=True)

    st.write("")
    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Key pool level over sessions")
        _pool_chart(adapter)
    with right:
        st.markdown("##### Key records (non-secret descriptors)")
        recs = adapter.key_records()
        if recs.empty:
            theme.note("No key records yet.")
        else:
            st.dataframe(recs.iloc[::-1], hide_index=True, use_container_width=True,
                         height=330)

    st.markdown("##### Lifecycle event log")
    st.dataframe(adapter.lifecycle_records(40), hide_index=True,
                 use_container_width=True)
    with st.expander("What the lifecycle states mean here"):
        st.markdown(
            "- **Pool records** (BB84 output held by the KMS): `AVAILABLE` - free "
            "to reserve; `RESERVED` - claimed by an in-flight request; `CONSUMED` "
            "- every bit spent; `EXPIRED` - TTL elapsed with bits unspent; "
            "`REVOKED` - withdrawn by policy; `DESTROYED` - buffer overwritten.\n"
            "- **Operational keys** (delivered AES keys): `ACTIVE`, `REVOKED`, "
            "`EXPIRED`, `DESTROYED`.\n"
            "- Revoked and expired are *not* sequential stages: a rekey revokes, "
            "expires and destroys the superseded key in one transaction, and a "
            "TTL sweep expires and destroys without a revocation. Only the "
            "transitions the framework actually performs appear in the log.\n"
            "- 'Destroyed' means the numpy buffer holding the bits is overwritten "
            "in place before the reference is dropped. That is best effort in "
            "CPython: it is not a claim of guaranteed secure erasure from process "
            "memory.")

    st.markdown("---")
    _secure_panel(adapter)


def _pool_chart(adapter: FrameworkAdapter) -> None:
    df = adapter.pool_history()
    if df.empty:
        theme.note("No pool history yet - run a session on the QKD Session "
                   "Monitor page.")
        return
    floor = adapter.key_pool_summary()["reserve_floor_bits"]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df["session_id"], y=df["total_available_bits"],
                             mode="lines+markers", name="Available secret bits",
                             line=dict(color=theme.BLUE, width=2), fill="tozeroy",
                             fillcolor="rgba(37,99,235,.10)"))
    fig.add_hline(y=floor, line_color="#dc2626", line_dash="dash",
                  annotation_text=f"reserve floor {floor:,} bits",
                  annotation_position="bottom left")
    fig.update_layout(height=330, margin=dict(l=8, r=8, t=10, b=8),
                      paper_bgcolor="white", plot_bgcolor="white",
                      yaxis_title="Available secret bits", xaxis_title="Session",
                      legend=dict(orientation="h", y=-0.25))
    st.plotly_chart(fig, use_container_width=True)


def _secure_panel(adapter: FrameworkAdapter) -> None:
    cfg = adapter.cfg
    st.markdown("#### Secure communication (local Alice/Bob demonstration)")
    theme.note("Both logical endpoints run inside this Python process, so the "
               "dashboard server is within the trusted boundary and does see "
               "plaintext. This is not browser-to-browser end-to-end encryption "
               "and no such claim is made.")

    a, b = st.columns([3, 2])
    with a:
        with st.form("send_form"):
            text = st.text_input("Alice's plaintext",
                                 value="Operational order: rotate credentials at 0600.",
                                 max_chars=cfg.max_message_bytes)
            t1, t2, t3 = st.columns(3)
            send = t1.form_submit_button("Send securely", type="primary")
            tamper_ct = t2.form_submit_button("Tamper before delivery")
            tamper_md = t3.form_submit_button("Tamper metadata")
        r1, r2 = st.columns(2)
        replay = r1.button("Replay the last delivered envelope")
    with b:
        # Filled after the action below, so the card shows post-action state.
        card_slot = st.empty()

    record = None
    if send:
        record = adapter.send_secure(text, tamper="none")
    elif tamper_ct:
        record = adapter.send_secure(text, tamper="ciphertext")
    elif tamper_md:
        record = adapter.send_secure(text, tamper="metadata")
    elif replay:
        record = adapter.replay_last()
        if record is None:
            theme.note("Nothing has been delivered yet, so there is no envelope "
                       "to replay.", warn=True)

    summary = adapter.messaging.summary()
    kid = summary["active_key_id"]
    with card_slot.container():
        theme.card("Active key", (kid[:8] if kid else "none yet"),
                   badge_text="ACTIVE" if kid else "PENDING", small=True,
                   sub=(f"{summary['algorithm']}. "
                        f"{summary['messages_remaining_under_active_key']} message(s) "
                        f"remaining under this key before a usage-limit rotation "
                        f"(policy: {cfg.max_messages_per_key} per key). "
                        f"Nonces claimed this process: {summary['nonces_claimed']}."))

    if record is not None:
        _render_outcome(adapter, record)

    if adapter.messaging.messages:
        st.markdown("##### Message log")
        st.dataframe(pd.DataFrame([{
            "seq": m.seq, "key_id": m.key_id[:8], "outcome": m.outcome,
            "plaintext_bytes": m.plaintext_len,
            "ciphertext_bytes": m.ciphertext_len,
            "rekey_trigger": m.rekey_trigger or "-",
        } for m in adapter.messaging.messages][::-1]),
            hide_index=True, use_container_width=True)
        st.caption("`rekey_trigger` distinguishes initial key acquisition, "
                   "usage-limit rotation, scheduled rotation and a control-plane "
                   "rekey. A per-message key allocation is not an AI threat "
                   "response and is not counted as one.")


def _render_outcome(adapter: FrameworkAdapter, record: sm.MessageRecord) -> None:
    title, explain = OUTCOME_TEXT.get(record.outcome, (record.outcome, ""))
    st.markdown("##### Result of this message")
    cols = st.columns(len(record.stages) or 1)
    for i, (col, (stage, note)) in enumerate(zip(cols, record.stages), start=1):
        bad = any(w in note.lower() for w in ("fail", "refus", "reject"))
        with col:
            theme.stage_card(i, stage, "FAILED" if bad else "COMPLETE", note)
    warn = record.outcome != sm.OUT_DELIVERED
    body = f"{title}. {explain}"
    if record.outcome == sm.OUT_DELIVERED:
        body += f" Bob received: \"{record.detail}\""
    else:
        body += f" Detail: {record.detail}"
    theme.note(body, warn=warn)
    st.caption("Exactly one outcome is reported per message.")

    env = adapter.messaging.stored_envelope(record.seq)
    if env is not None:
        with st.expander("Envelope detail (ciphertext, nonce, tag, authenticated metadata)"):
            ct = env["ciphertext"]
            st.code(
                f"connection      : {env['connection_id']}\n"
                f"key id          : {env['key_id']}\n"
                f"sequence        : {env['seq']}\n"
                f"algorithm       : {env['algorithm']}\n"
                f"nonce (hex)     : {env['nonce'].hex()}\n"
                f"authenticated   : {env['aad'].decode('utf-8')}\n"
                f"ciphertext bytes: {len(ct)} (last 16 bytes are the GCM tag)\n"
                f"ciphertext (hex): {ct[:48].hex()}{'...' if len(ct) > 48 else ''}\n"
                f"tag (hex)       : {ct[-16:].hex()}",
                language="text")
            st.caption("The authenticated metadata binds connection identity, key "
                       "id, sequence number and algorithm, so an envelope cannot "
                       "be replayed onto another connection or relabelled with a "
                       "different key id without failing authentication. No key "
                       "material is shown.")
