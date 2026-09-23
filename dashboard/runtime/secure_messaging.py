"""Application-layer secure messaging over QKD-delivered keys.

This module sits ON TOP of the notebook's ``QKDSecureChannel`` rather than
replacing it, and adds the four properties the notebook implementation does not
have.  Each is a deliberate, tested runtime addition, listed here because the
notebook's own results were not produced with them:

1. **Bound associated data.**  The notebook authenticates a constant
   ``b'qkd-e2e'``.  Here the AAD binds connection identity, key id, message
   sequence number and algorithm, so an envelope cannot be replayed onto a
   different connection or re-labelled with a different key id.
2. **Explicit replay protection.**  AES-GCM authentication accepts a *valid*
   envelope any number of times.  A per-(key_id, seq) receive ledger rejects the
   second delivery.
3. **Lifecycle re-validation at use time.**  The notebook's receiver caches key
   bytes by ``key_id`` and never re-checks state, so a cached key keeps
   decrypting after it has been revoked or has expired.  Here every send and
   every receive re-reads the lifecycle record and refuses a key that is not
   ACTIVE and unexpired.
4. **A nonce ledger that survives simulation reset.**  Nonces are deterministic
   in the sequence number, so uniqueness depends on never reusing a
   (key_id, seq) pair.  The ledger is process-scoped and is NOT cleared by
   "Reset Simulation", so a reset cannot resurrect a nonce.

TRUST BOUNDARY - stated, not worked around:
    This is a **local Alice/Bob encryption demonstration; the dashboard server
    is within the trusted boundary.**  Both logical endpoints run in one Python
    process, so the server necessarily sees plaintext.  This is NOT
    browser-to-browser end-to-end encryption and no such claim is made.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from dashboard.runtime import notebook_runtime as nr

AAD_VERSION = "qkd-e2e-v1"

# Rekey triggers, kept distinct so a usage-limit rotation is never reported as
# an AI threat response (and vice versa).
TRIGGER_INITIAL = "INITIAL_ACQUISITION"
TRIGGER_USAGE = "USAGE_LIMIT_ROTATION"
TRIGGER_SCHEDULED = "SCHEDULED_ROTATION"
TRIGGER_THREAT = "THREAT_TRIGGERED_ROTATION"
TRIGGER_SUPERSEDED = "CONTROL_PLANE_REKEY"

# Outcomes.  Exactly one is reported per message.
OUT_DELIVERED = "DELIVERED"
OUT_INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
OUT_REPLAY_REJECTED = "REPLAY_REJECTED"
OUT_INVALID_KEY = "INVALID_KEY"
OUT_PENDING_KEY = "PENDING_KEY_GENERATION"
OUT_EMPTY_POOL = "BLOCKED_EMPTY_POOL"
OUT_REFUSED = "REFUSED"


class NonceLedger:
    """(key_id, nonce) pairs already used for encryption, process-scoped.

    Deliberately NOT part of the resettable runtime: a simulation reset must not
    be able to make a previously used nonce look fresh.
    """

    def __init__(self) -> None:
        self._used: set[tuple[str, bytes]] = set()

    def claim(self, key_id: str, nonce: bytes) -> bool:
        pair = (key_id, nonce)
        if pair in self._used:
            return False
        self._used.add(pair)
        return True

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._used)


@dataclass
class MessageRecord:
    seq: int
    key_id: str
    outcome: str
    detail: str
    plaintext_len: int
    ciphertext_len: int
    at: float = field(default_factory=time.time)
    stages: list[tuple[str, str]] = field(default_factory=list)
    rekey_trigger: str | None = None


def build_aad(connection_id: str, key_id: str, seq: int, algorithm: str) -> bytes:
    """Authenticated (not encrypted) envelope metadata.

    Every field a receiver relies on to decide *what* it is decrypting is in
    here, so altering any of them fails authentication rather than silently
    decrypting under a different meaning.
    """
    return ("|".join([AAD_VERSION, f"conn={connection_id}", f"kid={key_id}",
                      f"seq={seq}", f"alg={algorithm}"])).encode("utf-8")


def bits_to_bytes(bits) -> bytes:
    b = np.asarray(bits, dtype=np.uint8)
    pad = (-len(b)) % 8
    if pad:
        raise ValueError(
            f"key material is {len(b)} bits, not a whole number of bytes. "
            "Refusing to pad: padding QKD output to reach an AES key length "
            "would substitute predictable zero bits for secret bits.")
    return np.packbits(b).tobytes()


class SecureMessagingService:
    """Alice and Bob, both local, over the framework's key-delivery API."""

    def __init__(self, api, lifecycle, connection_id: str, nonce_ledger: NonceLedger,
                 key_bits: int, max_messages_per_key: int = 8,
                 max_message_bytes: int = 2048):
        if key_bits not in (128, 192, 256):
            raise ValueError(f"AES-GCM requires a 128/192/256-bit key, not {key_bits}")
        self.api = api
        self.lifecycle = lifecycle
        self.connection_id = connection_id
        self.nonces = nonce_ledger
        self.key_bits = int(key_bits)
        self.algorithm = f"AES-{self.key_bits}-GCM"
        self.max_messages_per_key = max(1, int(max_messages_per_key))
        self.max_message_bytes = int(max_message_bytes)

        self._sender: dict[str, Any] | None = None
        self._envelopes: dict[int, dict[str, Any]] = {}
        self._receiver_cache: dict[str, bytes] = {}
        self._delivered: set[tuple[str, int]] = set()   # replay ledger
        self._seq = 0
        self.messages: list[MessageRecord] = []
        self.rekeys: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # lifecycle validity, re-checked at every use
    # ------------------------------------------------------------------
    def _record(self, key_id: str):
        return self.lifecycle.keys.get(key_id)

    def key_usable(self, key_id: str) -> tuple[bool, str]:
        rec = self._record(key_id)
        if rec is None:
            return False, "key id is unknown to the lifecycle manager"
        if rec["state"] != nr.KeyLifecycleManager.ACTIVE:
            return False, f"key state is {rec['state']}, not ACTIVE"
        if time.time() > rec["expires_at"]:
            return False, "key TTL has elapsed"
        return True, "ACTIVE"

    def active_control_plane_key(self) -> str | None:
        """The key id the CONTROL PLANE currently holds for this connection."""
        return self.lifecycle.active_by_conn.get(self.connection_id)

    # ------------------------------------------------------------------
    # key acquisition
    # ------------------------------------------------------------------
    def _adopt_control_plane_key(self) -> bool:
        """If the control plane rekeyed this connection, adopt that key.

        This is what makes an AI-issued rekey actually change the key the
        application uses, instead of the two living on separate connections.
        """
        kid = self.active_control_plane_key()
        if kid is None:
            return False
        if self._sender is not None and self._sender["key_id"] == kid:
            return False
        ok, _ = self.key_usable(kid)
        if not ok:
            return False
        rec = self._record(kid)
        self._sender = {"key_id": kid, "bytes": bits_to_bytes(rec["material"]),
                        "uses": 0, "expires_at": rec["expires_at"]}
        self.rekeys.append({"key_id": kid, "trigger": TRIGGER_SUPERSEDED,
                            "at": time.time()})
        return True

    def _acquire_key(self, trigger: str, session_id=None) -> dict[str, Any]:
        delivered = self.api.request_key(self.connection_id,
                                         key_length=self.key_bits,
                                         session_id=session_id)
        if int(delivered["key_length_bits"]) != self.key_bits:
            raise nr.KeyDeliveryError(
                f"delivered key is {delivered['key_length_bits']} bits but "
                f"{self.algorithm} requires {self.key_bits}. Refusing to pad or "
                f"substitute non-QKD material.")
        self._sender = {"key_id": delivered["key_id"],
                        "bytes": bits_to_bytes(delivered["key_bits"]),
                        "uses": 0, "expires_at": delivered["expires_at"]}
        self.rekeys.append({"key_id": delivered["key_id"], "trigger": trigger,
                            "at": time.time()})
        return self._sender

    def _ensure_sender_key(self, session_id=None) -> tuple[dict[str, Any] | None, str, str]:
        """Returns (key, trigger, note).  Raises KeyDeliveryError upward."""
        self._adopt_control_plane_key()
        if self._sender is None:
            return self._acquire_key(TRIGGER_INITIAL, session_id), TRIGGER_INITIAL, "initial key acquisition"
        ok, why = self.key_usable(self._sender["key_id"])
        if not ok:
            return (self._acquire_key(TRIGGER_SCHEDULED, session_id),
                    TRIGGER_SCHEDULED, f"previous key retired ({why})")
        if self._sender["uses"] >= self.max_messages_per_key:
            return (self._acquire_key(TRIGGER_USAGE, session_id),
                    TRIGGER_USAGE, "usage limit for this key reached")
        return self._sender, "", ""

    # ------------------------------------------------------------------
    # send / receive
    # ------------------------------------------------------------------
    def send_and_receive(self, plaintext: str, tamper: str = "none",
                         replay_of: int | None = None,
                         session_id=None) -> MessageRecord:
        """One message, one outcome.

        ``tamper`` is 'none', 'ciphertext' (flip a ciphertext bit in transit) or
        'metadata' (rewrite the authenticated key id in transit).
        ``replay_of`` re-delivers a previously sent envelope.
        """
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        stages: list[tuple[str, str]] = []

        # ---- replay path: re-deliver a stored envelope verbatim ----------
        if replay_of is not None:
            env = self._envelopes.get(replay_of)
            if env is None:
                return self._log(MessageRecord(self._seq, "-", OUT_REFUSED,
                                               "no stored envelope to replay",
                                               0, 0, stages=stages))
            stages.append(("Request/obtain key", "skipped (replay)"))
            stages.append(("Encrypt", "skipped (replay)"))
            stages.append(("Deliver envelope", "re-delivered verbatim"))
            return self._log(self._receive(dict(env), stages, replay=True))

        data = plaintext.encode("utf-8")
        if len(data) == 0:
            return self._log(MessageRecord(self._seq, "-", OUT_REFUSED,
                                           "empty message", 0, 0, stages=stages))
        if len(data) > self.max_message_bytes:
            return self._log(MessageRecord(self._seq, "-", OUT_REFUSED,
                                           f"message exceeds {self.max_message_bytes} bytes",
                                           len(data), 0, stages=stages))

        # ---- 1. request / obtain key -------------------------------------
        try:
            key, trigger, note = self._ensure_sender_key(session_id)
        except nr.KeyDeliveryError as exc:
            reason = str(exc)
            outcome = OUT_EMPTY_POOL if "POOL_EXHAUSTED" in reason else OUT_PENDING_KEY
            stages.append(("Request/obtain key", "failed"))
            return self._log(MessageRecord(self._seq, "-", outcome, reason,
                                           len(data), 0, stages=stages))
        ok, why = self.key_usable(key["key_id"])
        if not ok:
            stages.append(("Request/obtain key", f"refused: {why}"))
            return self._log(MessageRecord(self._seq, key["key_id"], OUT_INVALID_KEY,
                                           why, len(data), 0, stages=stages))
        stages.append(("Request/obtain key", f"{key['key_id'][:8]} ACTIVE"
                                             + (f" - {note}" if note else "")))

        # ---- 2. encrypt ---------------------------------------------------
        seq = self._seq
        nonce = seq.to_bytes(4, "big") + key["uses"].to_bytes(8, "big")
        if not self.nonces.claim(key["key_id"], nonce):
            stages.append(("Encrypt", "refused: nonce reuse"))
            return self._log(MessageRecord(seq, key["key_id"], OUT_REFUSED,
                                           "nonce already used under this key - refusing "
                                           "to encrypt (GCM nonce reuse is a total break)",
                                           len(data), 0, stages=stages))
        aad = build_aad(self.connection_id, key["key_id"], seq, self.algorithm)
        ct = AESGCM(key["bytes"]).encrypt(nonce, data, aad)
        key["uses"] += 1
        stages.append(("Encrypt", f"{self.algorithm}, {len(ct)} bytes incl. 16-byte tag"))

        env = {"connection_id": self.connection_id, "key_id": key["key_id"],
               "seq": seq, "nonce": nonce, "ciphertext": ct, "aad": aad,
               "algorithm": self.algorithm}
        self._envelopes[seq] = dict(env)
        self._seq += 1

        # ---- 3. deliver (with optional in-transit tampering) --------------
        wire = dict(env)
        if tamper == "ciphertext":
            mutated = bytearray(wire["ciphertext"])
            mutated[0] ^= 0x01
            wire["ciphertext"] = bytes(mutated)
            stages.append(("Deliver envelope", "ciphertext bit flipped in transit"))
        elif tamper == "metadata":
            wire["aad"] = build_aad(self.connection_id, key["key_id"], seq + 1,
                                    self.algorithm)
            stages.append(("Deliver envelope", "authenticated sequence number "
                                               "rewritten in transit"))
        else:
            stages.append(("Deliver envelope", "unmodified"))

        rec = self._receive(wire, stages)
        rec.rekey_trigger = trigger or None
        return self._log(rec)

    # ------------------------------------------------------------------
    def _receive(self, wire: dict[str, Any], stages: list[tuple[str, str]],
                 replay: bool = False) -> MessageRecord:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        kid, seq = wire["key_id"], wire["seq"]
        plen = 0

        ok, why = self.key_usable(kid)
        if not ok:
            stages.append(("Verify and decrypt", f"key refused: {why}"))
            self._receiver_cache.pop(kid, None)
            return MessageRecord(seq, kid, OUT_INVALID_KEY, why, plen,
                                 len(wire["ciphertext"]), stages=stages)

        # Both checks happen BEFORE any crypto. Lifecycle validity first (is
        # this key allowed at all?), then the replay ledger: a valid envelope
        # must not be accepted twice, and AES-GCM cannot tell the difference.
        # accepted twice, and AES-GCM cannot tell the difference.
        if (kid, seq) in self._delivered:
            stages.append(("Verify and decrypt", "rejected: sequence already delivered"))
            return MessageRecord(seq, kid, OUT_REPLAY_REJECTED,
                                 "envelope replays a sequence number already "
                                 "delivered under this key", plen,
                                 len(wire["ciphertext"]), stages=stages)

        if kid not in self._receiver_cache:
            try:
                delivered = self.api.get_key_with_key_id(self.connection_id, kid)
            except nr.KeyDeliveryError as exc:
                stages.append(("Verify and decrypt", "key fetch refused"))
                return MessageRecord(seq, kid, OUT_INVALID_KEY, str(exc), plen,
                                     len(wire["ciphertext"]), stages=stages)
            self._receiver_cache[kid] = bits_to_bytes(delivered["key_bits"])

        try:
            pt = AESGCM(self._receiver_cache[kid]).decrypt(
                wire["nonce"], wire["ciphertext"], wire["aad"])
        except InvalidTag:
            stages.append(("Verify and decrypt", "GCM authentication FAILED"))
            return MessageRecord(seq, kid, OUT_INTEGRITY_FAILURE,
                                 "authentication tag did not verify - the "
                                 "ciphertext or its authenticated metadata was "
                                 "altered", plen, len(wire["ciphertext"]),
                                 stages=stages)

        self._delivered.add((kid, seq))
        stages.append(("Verify and decrypt", "authenticated and decrypted"))
        return MessageRecord(seq, kid, OUT_DELIVERED, pt.decode("utf-8", "replace"),
                             len(pt), len(wire["ciphertext"]), stages=stages)

    # ------------------------------------------------------------------
    def _log(self, rec: MessageRecord) -> MessageRecord:
        self.messages.append(rec)
        return rec

    def stored_envelope(self, seq: int) -> dict[str, Any] | None:
        return self._envelopes.get(seq)

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for m in self.messages:
            counts[m.outcome] = counts.get(m.outcome, 0) + 1
        triggers: dict[str, int] = {}
        for r in self.rekeys:
            triggers[r["trigger"]] = triggers.get(r["trigger"], 0) + 1
        return {"messages": len(self.messages), "outcomes": counts,
                "rekeys_by_trigger": triggers,
                "active_key_id": self._sender["key_id"] if self._sender else None,
                "uses_of_active_key": self._sender["uses"] if self._sender else 0,
                "messages_remaining_under_active_key":
                    (self.max_messages_per_key - self._sender["uses"])
                    if self._sender else 0,
                "algorithm": self.algorithm,
                "nonces_claimed": len(self.nonces)}
