"""Page 2 - QKD Session Monitor: configure, run and inspect one BB84 session."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard import theme
from dashboard.adapter import FrameworkAdapter, SessionParams


def render(adapter: FrameworkAdapter) -> None:
    cfg = adapter.cfg
    st.subheader("QKD session monitor and verification")
    st.caption(f"{cfg.protocol_label}. Parameters below are simulator inputs "
               f"with the meanings the framework gives them; the channel noise "
               f"setting is a depolarising probability per photon, not the "
               f"resulting QBER.")

    busy = st.session_state.get("session_running", False)

    with st.form("session_form"):
        f1, f2, f3 = st.columns(3)
        with f1:
            n_bits = st.number_input(
                "Session size (photons Alice sends)",
                min_value=cfg.session_size_min, max_value=cfg.session_size_max,
                value=int(adapter.channel.n_bits), step=50,
                help=f"Bounded to {cfg.session_size_min}-{cfg.session_size_max} "
                     f"photons: one AerSimulator circuit runs per photon, so a "
                     f"million-pulse session is not a demo-scale run here.")
            seed = st.number_input("Seed (reproducible PRNG, not cryptographic)",
                                   min_value=0, value=int(adapter.channel.seed), step=1)
        with f2:
            error_rate = st.slider(
                "Channel depolarising probability", min_value=float(cfg.noise_min),
                max_value=float(cfg.noise_max), value=float(adapter.channel.error_rate),
                step=0.005, format="%.3f",
                help="Probability that a uniformly random Pauli hits a photon. "
                     "It is not the QBER, though it raises it.")
            sample_fraction = st.slider(
                "QBER sample fraction", min_value=float(cfg.sample_fraction_min),
                max_value=float(cfg.sample_fraction_max),
                value=float(adapter.channel.sample_fraction), step=0.05, format="%.2f",
                help="Fraction of the SIFTED key publicly sacrificed to estimate "
                     "QBER. Denominator is the sifted key length, not the photons sent.")
        with f3:
            eve_on = st.checkbox("Enable simulated eavesdropper",
                                 value=adapter.channel.eve_rate > 0)
            eve_rate = st.slider(
                "Configured interception rate", min_value=float(cfg.eve_min),
                max_value=float(cfg.eve_max),
                value=float(adapter.channel.eve_rate if adapter.channel.eve_rate else 0.3),
                step=0.05, format="%.2f", disabled=not eve_on,
                help="Fraction of photons an intercept-resend eavesdropper "
                     "measures and re-prepares. This is a SIMULATOR INPUT, "
                     "not something the detector discovered.")
            st.caption("Expected sifted bits ≈ session size / 2; expected sample "
                       f"bits ≈ that × {sample_fraction:.2f}.")
        run = st.form_submit_button("Run session", type="primary", disabled=busy)

    eve_value = float(eve_rate) if eve_on else 0.0
    rcol1, rcol2 = st.columns([1, 4])
    with rcol1:
        reset_clicked = st.button("Reset simulation", disabled=busy)
    if reset_clicked:
        st.session_state["confirm_reset"] = True
    if st.session_state.get("confirm_reset"):
        theme.note("Reset destroys the key pool, every operational key and all "
                   "telemetry for this browser session. The nonce ledger is "
                   "deliberately kept, so no previously used nonce can be "
                   "reused afterwards.", warn=True)
        d1, d2, _ = st.columns([1, 1, 4])
        if d1.button("Confirm reset", type="primary"):
            adapter.reset(hard=True)
            st.session_state["confirm_reset"] = False
            st.rerun()
        if d2.button("Cancel"):
            st.session_state["confirm_reset"] = False
            st.rerun()

    if run:
        params = SessionParams(n_bits=int(n_bits), error_rate=float(error_rate),
                               eve_rate=eve_value,
                               sample_fraction=float(sample_fraction), seed=int(seed))
        errs = params.validate(cfg)
        if errs:
            for e in errs:
                st.error(e)
        else:
            st.session_state["session_running"] = True
            try:
                with st.spinner(f"Running {params.n_bits} photons through the "
                                f"simulated channel..."):
                    adapter.run_session(params)
            finally:
                st.session_state["session_running"] = False
            st.rerun()

    st.markdown("---")

    if not adapter.sessions:
        theme.note("No session has been run yet. Configure the parameters above "
                   "and press Run session.")
        return

    last = adapter.sessions[-1]
    _params_cards(adapter, last)
    st.markdown("#### Protocol stages (actual completion, not animated)")
    _stages(last)
    st.markdown("#### Current session result")
    _result(adapter, last)
    st.markdown("#### Recent sessions")
    df = adapter.telemetry_snapshot(cfg.history_rows).iloc[::-1]
    st.dataframe(df, hide_index=True, use_container_width=True,
                 column_config={
                     "qber_observed": st.column_config.NumberColumn("QBER observed", format="%.4f"),
                     "qber_upper_bound": st.column_config.NumberColumn(
                         f"QBER {cfg.qber_confidence:.0%} upper bound", format="%.4f"),
                     "configured_interception": st.column_config.NumberColumn(
                         "Configured interception", format="%.2f"),
                     "configured_noise": st.column_config.NumberColumn(
                         "Configured noise", format="%.3f"),
                     "reason": st.column_config.TextColumn("Reason", width="medium"),
                 })
    st.caption("Sessions marked 'replenishment' were generated by the key "
               "lifecycle manager to restock the pool. They run over the same "
               "configured channel conditions as operator sessions - the "
               "eavesdropper is never switched off to make replenishment succeed.")


def _params_cards(adapter: FrameworkAdapter, last) -> None:
    p = last.params
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        theme.card("Session size", f"{p['n_bits']:,}", "photons",
                   sub=f"Protocol: {adapter.cfg.protocol_label}. "
                       f"Quantum-channel time {last.channel_time_sec * 1000:.2f} ms at "
                       f"the assumed 1 MHz pulse rate; simulator wall-clock "
                       f"{last.wall_time_sec:.2f} s. These are different quantities.")
    with c2:
        theme.card("Channel depolarising probability", f"{p['error_rate'] * 100:.2f}", "%",
                   sub="Per-photon probability of a random Pauli error. No fibre "
                       "length, attenuation or detector model is involved.")
    with c3:
        eve = p["eve_rate"]
        theme.card("Configured interception", f"{eve * 100:.2f}", "%",
                   badge_text="EVE ENABLED" if eve > 0 else "EVE DISABLED",
                   sub="Simulator input chosen by the operator. It is not a "
                       "detection result, so 0% means 'configured interception: "
                       "0%', not 'no interception detected'.")
    with c4:
        theme.card("QBER sample fraction", f"{p['sample_fraction'] * 100:.1f}", "%",
                   sub=(f"Of the sifted key. {last.sample_bits} bits sampled from "
                        f"{last.sifted_bits} sifted bits"
                        if last.sample_bits else "Sifting did not complete."))


def _stages(last) -> None:
    rows = last.stages
    for chunk_start in range(0, len(rows), 5):
        chunk = rows[chunk_start:chunk_start + 5]
        cols = st.columns(len(chunk))
        for j, (col, s) in enumerate(zip(cols, chunk)):
            with col:
                theme.stage_card(chunk_start + j + 1, s["stage"],
                                 "COMPLETE" if s["state"] == "complete" else "NOT REACHED",
                                 s["note"])


def _result(adapter: FrameworkAdapter, last) -> None:
    cfg = adapter.cfg
    c1, c2 = st.columns([2, 3])
    with c1:
        theme.card("Session ID", f"SES-{last.session_id:04d}",
                   badge_text="ACCEPTED" if last.accepted else "ABORTED",
                   small=True,
                   sub=(f"Origin: {last.params.get('origin')}. "
                        f"{'Accepted under the configured simulation checks.' if last.accepted else 'Abort reason: ' + last.reason}"))
        theme.card("Final accepted secret bits", f"{last.final_secret_bits:,}", "bits",
                   sub=(f"{last.admitted_bits:,} bits admitted to the key pool "
                        f"after the authentication reserve was paid first."
                        if last.accepted else
                        "No key material was produced, so nothing entered the pool."))
    with c2:
        qp = "-" if last.qber_point is None else f"{last.qber_point * 100:.2f}%"
        qu = "-" if last.qber_upper is None else f"{last.qber_upper * 100:.2f}%"
        st.dataframe(pd.DataFrame([
            {"quantity": "Observed QBER (point estimate)", "value": qp,
             "note": "what an operator observes; the feature the detector sees"},
            {"quantity": f"QBER upper confidence bound ({cfg.qber_confidence:.0%}, one-sided)",
             "value": qu,
             "note": "Clopper-Pearson exact binomial; this is what the abort "
                     "decision is made on"},
            {"quantity": "Abort threshold", "value": f"{cfg.qber_abort_threshold:.1%}",
             "note": "asymptotic Shor-Preskill value used as a simulation "
                     "threshold; not a finite-key security claim"},
            {"quantity": "Sifted bits", "value": f"{last.sifted_bits or '-'}",
             "note": "positions where Alice's and Bob's bases agreed"},
            {"quantity": "Sampled bits / errors",
             "value": f"{last.sample_bits or '-'} / {last.sample_errors or '-'}",
             "note": "sample drawn from the sifted key and discarded afterwards"},
            {"quantity": "Status", "value": "ACCEPTED" if last.accepted else "ABORTED",
             "note": last.reason},
        ]), hide_index=True, use_container_width=True)
    if last.accepted:
        theme.note("Accepted under the configured simulation checks: the QBER "
                   "upper bound was below the abort threshold, the classical "
                   "channel authenticated, reconciliation and key verification "
                   "succeeded, and privacy amplification produced a non-empty "
                   "key. This is a simulation acceptance test, not a proof of "
                   "information-theoretic security for the resulting bits.")
    else:
        theme.note(f"Session aborted: {last.reason}. No bits from an aborted "
                   f"session can enter the key pool - the pool refuses insecure "
                   f"material outright, so aborted material can never be spliced "
                   f"into an operational key.", warn=True)

    with st.expander("Privacy amplification and disclosure accounting"):
        st.write(f"Privacy amplification state: "
                 f"**{'completed' if last.final_secret_bits else 'produced no extractable key'}**.")
        st.caption("The framework's composable security parameters are defined in "
                   "the notebook (eps_secrecy, eps_correctness, eps_PA) but the "
                   "extraction here is asymptotic, so no finite-key epsilon "
                   "assertion is made about these bits.")
