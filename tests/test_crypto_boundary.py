"""Cryptographic boundary: §14 items 4-8 and 16."""
from __future__ import annotations

import time

import pytest

from dashboard.runtime import notebook_runtime as nr
from dashboard.runtime import secure_messaging as sm
from tests.conftest import stock_pool


def test_valid_message_round_trips(stocked):
    rec = stocked.send_secure("the quick brown fox")
    assert rec.outcome == sm.OUT_DELIVERED
    assert rec.detail == "the quick brown fox"


def test_modified_ciphertext_is_rejected(stocked):
    rec = stocked.send_secure("payload", tamper="ciphertext")
    assert rec.outcome == sm.OUT_INTEGRITY_FAILURE


def test_modified_authenticated_metadata_is_rejected(stocked):
    rec = stocked.send_secure("payload", tamper="metadata")
    assert rec.outcome == sm.OUT_INTEGRITY_FAILURE


def test_replayed_envelope_is_rejected(stocked):
    first = stocked.send_secure("replay me")
    assert first.outcome == sm.OUT_DELIVERED
    again = stocked.replay_last()
    assert again.outcome == sm.OUT_REPLAY_REJECTED, (
        "AES-GCM authenticates a replayed envelope perfectly well; the replay "
        "ledger is what must reject it")


def test_nonce_reuse_under_one_key_is_refused(stocked):
    stocked.send_secure("first")
    svc = stocked.messaging
    key = svc._sender
    # Force the deterministic nonce to repeat, exactly as a restart bug would.
    svc._seq = 0
    key["uses"] = 0
    rec = svc.send_and_receive("second under the same nonce")
    assert rec.outcome == sm.OUT_REFUSED
    assert "nonce" in rec.detail.lower()


def test_nonce_ledger_survives_reset(adapter):
    stock_pool(adapter, 2048)
    adapter.send_secure("before reset")
    claimed_before = len(adapter.nonce_ledger)
    adapter.reset()
    assert len(adapter.nonce_ledger) == claimed_before, (
        "a reset must not clear the nonce ledger")


def test_expired_cached_key_cannot_bypass_policy(stocked):
    """The notebook's receiver caches key bytes by key_id and never re-checks
    state.  Here the cache must not survive expiry."""
    rec = stocked.send_secure("first under this key")
    assert rec.outcome == sm.OUT_DELIVERED
    kid = rec.key_id
    assert kid in stocked.messaging._receiver_cache

    stocked.lifecycle.keys[kid]["expires_at"] = time.time() - 1.0
    ok, why = stocked.messaging.key_usable(kid)
    assert not ok and "TTL" in why

    env = stocked.messaging.stored_envelope(rec.seq)
    replayed = stocked.messaging.send_and_receive("", replay_of=rec.seq)
    assert replayed.outcome == sm.OUT_INVALID_KEY
    assert kid not in stocked.messaging._receiver_cache


def test_revoked_key_cannot_encrypt_new_traffic(stocked):
    rec = stocked.send_secure("first")
    kid = rec.key_id
    stocked.lifecycle.revoke_old_key(kid, "test revocation")
    ok, why = stocked.messaging.key_usable(kid)
    assert not ok and "REVOKED" in why
    # A new send must obtain a different key rather than reuse the revoked one.
    second = stocked.send_secure("second")
    assert second.key_id != kid


def test_key_length_must_match_the_aes_variant(stocked):
    from dashboard.runtime.secure_messaging import bits_to_bytes
    with pytest.raises(ValueError) as exc:
        bits_to_bytes([1, 0, 1])          # 3 bits: not a whole number of bytes
    assert "refusing to pad" in str(exc.value).lower()

    with pytest.raises(ValueError):
        sm.SecureMessagingService(stocked.api, stocked.lifecycle, "c",
                                  stocked.nonce_ledger, key_bits=200)


def test_export_contains_no_raw_key_material(stocked):
    stocked.send_secure("sensitive payload")
    blob = stocked.export_events()
    assert "sensitive payload" not in blob
    for forbidden in ('"material"', '"key_bits"', '"ciphertext":'):
        assert forbidden not in blob or "<redacted>" in blob
    # The key ids themselves are fine; the bits are not.
    key_id = stocked.messaging.summary()["active_key_id"]
    rec = stocked.lifecycle.keys[key_id]
    bits = "".join(str(int(b)) for b in rec["material"][:32])
    assert bits not in blob


def test_aad_binds_connection_key_and_sequence():
    a = sm.build_aad("alice<->bob", "K1", 3, "AES-256-GCM")
    for other in (sm.build_aad("alice<->eve", "K1", 3, "AES-256-GCM"),
                  sm.build_aad("alice<->bob", "K2", 3, "AES-256-GCM"),
                  sm.build_aad("alice<->bob", "K1", 4, "AES-256-GCM"),
                  sm.build_aad("alice<->bob", "K1", 3, "AES-128-GCM")):
        assert a != other
