"""Streamlit AppTest coverage: §14 items 1-3."""
from __future__ import annotations

import pytest
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")

PAGES = ["Overview", "QKD Session Monitor", "Key Pool and Lifecycle"]


def _app() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=180)
    at.run()
    return at


def test_all_three_pages_load():
    at = _app()
    assert not at.exception
    radio = at.radio[0]
    assert list(radio.options) == PAGES
    for page in PAGES:
        at.radio[0].set_value(page).run()
        assert not at.exception, f"{page} raised {at.exception}"


def test_navigation_and_refresh_preserve_state():
    at = _app()
    adapter = at.session_state["adapter"]
    adapter_id = id(adapter)
    at.radio[0].set_value("Key Pool and Lifecycle").run()
    at.radio[0].set_value("Overview").run()
    assert id(at.session_state["adapter"]) == adapter_id, (
        "navigation must not rebuild the runtime")
    # "Refresh display" is a read-only redraw.
    refresh = [b for b in at.button if "Refresh" in b.label][0]
    refresh.click().run()
    assert id(at.session_state["adapter"]) == adapter_id
    assert not at.exception


def test_redraw_runs_no_qkd_session_and_allocates_no_key():
    at = _app()
    adapter = at.session_state["adapter"]
    before_sessions = len(adapter.sessions)
    before_records = len(adapter.qber_exporter.records)
    before_requests = adapter.key_pool.requests_total

    for page in PAGES + PAGES:
        at.radio[0].set_value(page).run()
    [b for b in at.button if "Refresh" in b.label][0].click().run()

    adapter = at.session_state["adapter"]
    assert len(adapter.sessions) == before_sessions
    assert len(adapter.qber_exporter.records) == before_records
    assert adapter.key_pool.requests_total == before_requests
    assert adapter.last_decision["available"] is False


@pytest.mark.slow
def test_run_session_button_executes_exactly_one_operator_session():
    at = _app()
    at.radio[0].set_value("QKD Session Monitor").run()
    # keep it small so the test stays quick
    at.number_input[0].set_value(400).run()
    run_btn = [b for b in at.button if b.label == "Run session"][0]
    run_btn.click().run()
    assert not at.exception
    adapter = at.session_state["adapter"]
    operator = [s for s in adapter.sessions if s.params.get("origin") == "operator"]
    assert len(operator) == 1
    assert adapter.last_decision["available"] is True


@pytest.mark.slow
def test_key_pool_page_renders_with_a_populated_lifecycle_audit():
    """Regression: audit rows for pool-level operations carry no key_id, which
    pandas renders as a float NaN. Shortening it naively raised a TypeError and
    broke the whole page."""
    at = _app()
    adapter = at.session_state["adapter"]

    import numpy as np
    from tests.conftest import stock_pool
    stock_pool(adapter, 2048)
    adapter.send_secure("populate the audit log")
    adapter.lifecycle.generate_key_material(target_bits=0)   # a key_id-less row

    audit = adapter.lifecycle.audit_dataframe()
    assert audit["key_id"].isna().any(), "fixture must include a key_id-less row"

    at.radio[0].set_value("Key Pool and Lifecycle").run()
    assert not at.exception, at.exception
