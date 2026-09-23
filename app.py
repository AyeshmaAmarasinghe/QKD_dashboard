"""Adaptive QKD Key Management - research dashboard.

An AI-Assisted Adaptive Key Management Framework for QKD-Enabled End-to-End
Secure Communication.  Research prototype - simulated QKD.

Run locally:

    python -m streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="Adaptive QKD Key Management",
                   page_icon="*", layout="wide",
                   initial_sidebar_state="collapsed")

from dashboard import theme  # noqa: E402
from dashboard.adapter import FrameworkAdapter  # noqa: E402
from dashboard.config import load_config  # noqa: E402
from dashboard.runtime.secure_messaging import NonceLedger  # noqa: E402
from dashboard.views import key_pool as view_key_pool  # noqa: E402
from dashboard.views import overview as view_overview  # noqa: E402
from dashboard.views import session_monitor as view_session  # noqa: E402

PAGES = ["Overview", "QKD Session Monitor", "Key Pool and Lifecycle"]


def get_adapter() -> FrameworkAdapter:
    """One runtime per browser session.

    Deliberately NOT ``st.cache_resource``: that shares one mutable object - and
    therefore one key store and one nonce counter - across every user of the
    server.  ``st.session_state`` keeps it per session.
    """
    if "nonce_ledger" not in st.session_state:
        st.session_state.nonce_ledger = NonceLedger()
    if "adapter" not in st.session_state:
        cfg = load_config()
        st.session_state.adapter = FrameworkAdapter(cfg, st.session_state.nonce_ledger)
    return st.session_state.adapter


def header(adapter: FrameworkAdapter, page: str) -> None:
    cfg = adapter.cfg
    net = adapter.net_source.status.replace("_", " ").title()
    chips = [
        f'<span class="chip">{theme.esc(cfg.protocol_label)}</span>',
        '<span class="chip">Simulation Telemetry</span>',
        f'<span class="chip">Sessions run: {len(adapter.sessions)}</span>',
        f'<span class="chip">Network model: {theme.esc(net)}</span>',
        f'<span class="chip">{theme.esc(cfg.provenance_label)}</span>',
    ]
    st.markdown(
        '<div class="qkd-header">'
        '<span class="brand">Adaptive QKD Key Management</span>'
        '<span class="spacer"></span>' + "".join(chips) + "</div>",
        unsafe_allow_html=True)


def main() -> None:
    theme.inject()
    adapter = get_adapter()

    if "page" not in st.session_state:
        st.session_state.page = PAGES[0]

    header(adapter, st.session_state.page)

    nav, _, refresh = st.columns([6, 3, 1.4])
    with nav:
        page = st.radio("Page", PAGES, horizontal=True,
                        index=PAGES.index(st.session_state.page),
                        label_visibility="collapsed", key="page")
    with refresh:
        # Read-only redraw. It runs NO session, allocates NO key and touches no
        # state; Streamlit reruns the script and the views re-read the runtime.
        st.button("Refresh display", use_container_width=True,
                  help="Redraw from current state. Does not run a QKD session.")

    if page == "Overview":
        view_overview.render(adapter)
    elif page == "QKD Session Monitor":
        view_session.render(adapter)
    else:
        view_key_pool.render(adapter)

    st.markdown("---")
    st.caption(
        f"{adapter.cfg.provenance_label}. Simulated BB84 over a depolarising "
        f"channel with an optional intercept-resend eavesdropper; no physical "
        f"laser, fibre or hardware telemetry is involved and no fibre distance "
        f"is modelled. Local Alice/Bob encryption demonstration; the dashboard "
        f"server is within the trusted boundary.")


if __name__ == "__main__":
    main()
