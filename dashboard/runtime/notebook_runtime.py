"""GENERATED FILE - DO NOT EDIT BY HAND.

Runtime definitions extracted verbatim from the research notebook
``nb.ipynb`` by ``tools/extract_runtime.py``.

Only class/function definitions and module-level constants are copied.  Every
demonstration run, training loop, dataset load, sweep, pip install and display
call in the notebook is excluded, so importing this module has no side effects
beyond defining names.

Source-cell mapping is printed below and is also available programmatically as
``SOURCE_CELL_MAP``.

Regenerate with::

    python tools/extract_runtime.py --notebook <path-to-notebook>
"""
# flake8: noqa
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import threading
import time
import uuid

import numpy as np
import pandas as pd

NOTEBOOK_SOURCE = 'nb.ipynb'
NOTEBOOK_SHA256 = 'fe744f1b3465a8c2cc8e1687700efc35c7d8a4a8404c974691997270bcd57785'
SOURCE_CELL_MAP = {'config': {'notebook_cell_index': 6, 'provides': 'SEED, make_rng, crypto_rng, AUTH_*, OPERATIONAL_KEY_BITS, KEY_MIN_BITS, KEY_TTL_SEC, BB84_SESSION_SIZES, EPS_*, default_usage_policy'}, 'alice': {'notebook_cell_index': 8, 'provides': 'Alice'}, 'channel': {'notebook_cell_index': 10, 'provides': 'QuantumChannel (depolarising noise, Eve intercept-resend, loss)'}, 'bob': {'notebook_cell_index': 12, 'provides': 'Bob'}, 'sifting': {'notebook_cell_index': 14, 'provides': 'BB84KeySifting'}, 'auth': {'notebook_cell_index': 16, 'provides': 'AuthenticationError, AuthKeyReserve, toeplitz_tag, AuthenticatedClassicalChannel'}, 'qber': {'notebook_cell_index': 18, 'provides': 'QBERCalculator (point estimate + one-sided upper bound)'}, 'ec': {'notebook_cell_index': 20, 'provides': 'ErrorCorrection (Cascade with look-back)'}, 'verify': {'notebook_cell_index': 22, 'provides': 'key_verification_tag, keys_agree'}, 'pa': {'notebook_cell_index': 24, 'provides': 'PrivacyAmplification (Toeplitz universal hashing)'}, 'kms': {'notebook_cell_index': 26, 'provides': 'KeyStatus, KeyPool, SynchronizedKeyStores, BB84Metrics'}, 'session': {'notebook_cell_index': 30, 'provides': 'run_bb84_simulation'}, 'lifecycle': {'notebook_cell_index': 32, 'provides': 'KeyLifecycleManager'}, 'delivery': {'notebook_cell_index': 34, 'provides': 'KeyDeliveryError, QKDKeyDeliveryAPI'}, 'secure_channel': {'notebook_cell_index': 36, 'provides': 'KeyReuseViolation, QKDSecureChannel (AES-GCM base class)'}, 'exporters': {'notebook_cell_index': 52, 'provides': 'QBERStreamExporter, PoolLevelExporter'}, 'monitored': {'notebook_cell_index': 54, 'provides': 'run_monitored_session'}, 'features': {'notebook_cell_index': 56, 'provides': 'FEATURE_COLS, LABEL_COL, extract_features'}, 'detector': {'notebook_cell_index': 60, 'provides': 'BaseAnomalyDetector, QKDAnomalyDetector, temporal_split (definitions only - no training)'}, 'nids_adapter': {'notebook_cell_index': 66, 'provides': 'NIDSFeatureError, NIDSThreatAdapter, GatedNetworkThreatDetector, load_nids_adapter (strict gate only - Kaggle path discovery and the legacy loader are NOT extracted)'}, 'forecaster': {'notebook_cell_index': 68, 'provides': 'PoolDemandForecaster (definition only - not fitted here)'}, 'scheduler': {'notebook_cell_index': 70, 'provides': 'AdaptiveScheduler'}, 'decision': {'notebook_cell_index': 74, 'provides': 'DecisionEngine + cost-derived thresholds (anomaly_threshold_watch/alert/high)'}, 'rekeying': {'notebook_cell_index': 93, 'provides': 'RekeyingCommandInterface'}, 'telemetry_logger': {'notebook_cell_index': 95, 'provides': 'SessionTelemetryLogger'}}

# TensorFlow is optional in the notebook and is deliberately NOT a dependency of
# the dashboard: PoolDemandForecaster falls back to the scikit-learn MLP path.
try:  # pragma: no cover - environment dependent
    import tensorflow as _tf  # noqa: F401
    HAS_TENSORFLOW = True
except Exception:  # pragma: no cover
    HAS_TENSORFLOW = False

# The notebook prints status banners at module level.  Those are useful in a
# notebook and noise in a server process, so `print` is a no-op for the duration
# of the extracted block and is restored at the end of this file.  Because
# Python resolves globals at call time, methods that print when `verbose=True`
# are unaffected once it is restored.
_real_print = print


def print(*args, **kwargs):  # noqa: A001 - intentional, restored below
    return None


# ===================================================================
# notebook cell [6] -> config
#   provides: SEED, make_rng, crypto_rng, AUTH_*, OPERATIONAL_KEY_BITS, KEY_MIN_BITS, KEY_TTL_SEC, BB84_SESSION_SIZES, EPS_*, default_usage_policy
# ===================================================================
# Core imports + single reproducible random source
import time
import hashlib
import numpy as np
import pandas as pd
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

# --- Reproducibility ---------------------------------------------------
# Fix #16: standardise on ONE random source. All stochastic code takes an
# explicit numpy Generator (rng) rather than mixing `random`, np.random.seed,
# and default_rng. The AerSimulator is also seeded explicitly (seed_simulator).
SEED = 42

def make_rng(seed=SEED):
    """Return a fresh, independent numpy Generator seeded deterministically.

    *** NOT CRYPTOGRAPHIC RANDOMNESS. ***

    Fix (2026-09-12, RANDOMNESS PROVENANCE NEVER STATED): this is
    numpy.random.default_rng - a PCG64 pseudo-random generator. It is
    deterministic, seeded, and its entire future output is predictable from its
    internal state. That is exactly what a reproducible experiment needs, and it
    is exactly what key generation must never use.

    Everything random in this notebook comes from here: Alice's bits and bases,
    Bob's bases, Eve's bases, channel noise, the Toeplitz seed for privacy
    amplification, the QBER sample indices, and the Cascade permutations. The
    keys this notebook produces are therefore REPRODUCIBLE SIMULATION ARTEFACTS,
    not secret key material - anyone holding the seed can regenerate every key.
    This is a property of the experiment, not a defect in BB84.

    In a deployment, the bit and basis choices must come from a quantum random
    number generator (the physical justification for BB84's security in the
    first place), or failing that from the operating system CSPRNG. See
    crypto_rng() below for that substitution point. It is provided and tested
    but NOT used by default, because switching it on would destroy
    reproducibility - every run would give different QBER values, different
    telemetry and different Step 11 confidence intervals.
    """
    return np.random.default_rng(seed)


def crypto_rng():
    """A cryptographically secure Generator, for a DEPLOYMENT path only.

    Seeds numpy's PCG64 from os.urandom via SeedSequence's entropy pool, so the
    output is unpredictable and unreproducible. This is the substitution point a
    real system would use - better still, entropy from a QRNG feeding the same
    interface.

    NOT used anywhere in this notebook by default. Every result here is produced
    with make_rng(SEED) so it can be reproduced. Passing crypto_rng() into
    run_bb84_simulation() works and demonstrates the deployment path, but the
    run is then non-reproducible by construction.
    """
    import secrets
    return np.random.default_rng(np.random.SeedSequence(
        secrets.randbits(128)))


# --- Classical-channel authentication (Wegman-Carter) -------------------
# BB84's security proof ASSUMES an authenticated classical channel. Without it,
# Eve runs BB84 separately with each party and both accept a key she holds,
# while QBER looks perfect. These parameters make that assumption explicit and
# charge what it costs.
AUTH_TAG_BITS = 32          # forgery probability <= 2^-32 per message
AUTH_MODE = 'transcript'    # 'transcript' (ONE tag per session over the whole
                            #   public transcript - deployment-style delayed
                            #   authentication) or 'per_phase' (one tag per
                            #   protocol phase - four tags, earlier rejection).
                            #
                            # DEFAULT 'transcript', and this is a MEASURED
                            # choice, not a convenience. At these session sizes
                            # per-phase authentication costs 4 x 32 = 128 bits
                            # while a session yields ~114 secret bits, so the
                            # link consumes more key than it produces: it runs
                            # net negative, lives off the bootstrap key, and
                            # eventually cannot authenticate at all (measured:
                            # expansion factor 0.02 over 40 sessions).
                            # Transcript mode authenticates exactly the same
                            # four messages for 32 bits, leaving the link
                            # comfortably net positive. The authentication-cost
                            # section measures both modes side by side.
AUTH_BOOTSTRAP_BITS = 4096  # ITEM 17: the PRE-SHARED key Alice and Bob must
                            # already hold, established OUT OF BAND. Not QKD
                            # output. This is why QKD is key EXPANSION, not key
                            # generation from nothing.
VERIFY_TAG_BITS = 32        # ITEM 18: key-verification tag length.
                            # Verification-failure probability <= 2^-32.

# Where the randomness comes from, stated once, in the output.
RANDOMNESS_SOURCE = "numpy PCG64 (seeded, reproducible) - NOT cryptographic"

# Assumed hardware pulse rate for physically-meaningful key-rate metrics.
# (Fix #19: key rate must derive from quantum channel time, not wall clock.)
PULSE_RATE_HZ = 1_000_000  # 1 MHz source; time per photon = 1 / PULSE_RATE_HZ s

# --- Operational key sizing --------------------------------------------
# Fix (2026-09-12, KEY LENGTH TOO SHORT): every rekey in this notebook used to
# draw key_length=64 bits. 64 bits is not a usable operational key for any
# modern symmetric cipher - AES takes 128/192/256, and a 64-bit key is
# brute-forceable, so a QKD framework delivering 64-bit keys throws away the
# security it spent a quantum channel to earn. Operational keys are now
# OPERATIONAL_KEY_BITS (default 256 = AES-256) and KEY_MIN_BITS is enforced at
# the key-delivery boundary.
#
# Decision (2026-09-12): 256 bits is NOT bought by making every BB84 session big
# enough to fund a whole key on its own. Sizing sessions at ~1.5k-2.8k photons
# would cost 4-5x the Qiskit runtime and force Step 11 to run fewer seeds, i.e.
# it would trade statistical power for an unnecessary architectural constraint.
# Instead, sessions stay MODERATE (500-1000 photons) and the KMS accumulates
# secret bits across several SECURE sessions until it has 256 - which is what a
# real key buffer does anyway. So: AES-256 operational keys at roughly the old
# runtime. See KeyPool.retrieve_key (splicing) and KeyPool.store_key (the
# secure-sessions-only invariant that makes splicing safe).
#
# Nothing else in the notebook hard-codes a key length - every consumer reads
# OPERATIONAL_KEY_BITS.
OPERATIONAL_KEY_BITS = 256          # 128 or 256; 256 = AES-256
KEY_MIN_BITS = 128                  # refuse to deliver anything shorter
KEY_TTL_SEC = 300.0                 # operational key lifetime before EXPIRE_KEY

# Measured end-to-end yield of this BB84 implementation at QBER <= 5%:
#   sifting ~0.50 -> QBER sample keeps 0.75 -> privacy amplification ~0.50
#   => ~0.19 secret bits per photon sent.
SECRET_BITS_PER_PHOTON = 0.19     # re-measured 2026-09-12, see below


def session_bits_for(key_bits=None, safety=1.10):
    """Photons Alice must send for one session's privacy amplification to
    normally yield >= key_bits secret bits (rounded up to 100)."""
    kb = int(OPERATIONAL_KEY_BITS if key_bits is None else key_bits)
    n = kb / SECRET_BITS_PER_PHOTON * safety
    return int(np.ceil(n / 100.0) * 100)


# Session sizes used by the telemetry generators. Deliberately MODERATE: at
# ~0.19 secret bits per photon these yield roughly 95 / 140 / 190 bits per
# secure session, so one operational key is assembled from ~2 sessions by
# KeyPool splicing. The spread is kept because the forecaster needs to see both
# pool growth and pool pressure.
BB84_SESSION_SIZES = (500, 750, 1000)

# For reference only - the session size that WOULD fund a whole key on its own.
# Printed below so the gap between "single-session sufficient" and the sizes
# actually used is explicit rather than hidden.
SINGLE_SESSION_SUFFICIENT_BITS = session_bits_for()

# --- Key demand schedule (derived, not hard-coded) ----------------------
# Fix (2026-09-12, POOL ECONOMICS): the telemetry generator used to retrieve a
# key every rng.integers(2, 4) sessions. That was tuned for 64-bit keys: at
# ~38 secret bits per generated session, demand was 25.6 bits/session, i.e.
# about 0.67 of supply, so the pool grew steadily and the replay window had
# inventory to work with. Quadrupling the key length WITHOUT rescaling the
# interval makes demand 102 bits/session against ~85 supplied - the pool runs
# net negative, and the AI arm then starves on DEFERRED_KEY_SCARCITY /
# FAILED_NO_KEY_AVAILABLE. That would look like a control-plane result and
# would actually be an arithmetic error, so the interval is now DERIVED to hold
# the original demand-to-supply ratio at any key length.
#
# Supply per GENERATED session (not per secure session): ~40% of the generated
# sessions carry Eve and abort at the QBER gate, contributing nothing.
# Re-measured 2026-09-12 after the abort decision moved to the QBER upper
# confidence bound: more sessions now abort (the bound is above the point
# estimate by construction), so the fraction of GENERATED sessions that yield
# key material fell from ~0.60 to ~0.53. Under-stating this would make the
# derived demand interval too aggressive and drain the pool.
SECURE_SESSION_FRACTION = 0.52        # conservative floor; the generator
                                      # prints the realised figure, see below
DEMAND_TO_SUPPLY_RATIO = 0.67         # preserved from the 64-bit configuration

EXPECTED_SECRET_BITS_PER_SESSION = (float(np.mean(BB84_SESSION_SIZES))
                                    * SECRET_BITS_PER_PHOTON
                                    * SECURE_SESSION_FRACTION)
KEY_RETRIEVAL_INTERVAL = max(2, int(round(
    OPERATIONAL_KEY_BITS / (DEMAND_TO_SUPPLY_RATIO * EXPECTED_SECRET_BITS_PER_SESSION))))
RETRIEVE_EVERY = (KEY_RETRIEVAL_INTERVAL, KEY_RETRIEVAL_INTERVAL + 3)
MEAN_RETRIEVE_INTERVAL = (RETRIEVE_EVERY[0] + RETRIEVE_EVERY[1] - 1) / 2.0


# --- Finite-key / statistical treatment switches ------------------------
# Privacy amplification subtracts h(QBER). Which QBER?
#
#   - The ABORT DECISION always uses the one-sided upper confidence bound
#     (QBERCalculator.USE_UPPER_BOUND, not this switch). That is settled: a
#     session is accepted only if the true error rate is below threshold at the
#     stated confidence.
#   - PA's entropy term is this switch, and it is a separate question.
#
# DEFAULT False, deliberately. At the session sizes used here the QBER sample is
# only ~90 bits, so the 99% upper bound sits far above the point estimate
# (measured: 3.2% -> 10.4%) and h() of it roughly HALVES the secret bits per
# session. That penalty is an artefact of small-sample statistics, not of any
# physical insecurity, and this notebook explicitly does not claim
# information-theoretic security for its keys (see the Research Boundary section
# and the finite-key comparison, which shows these block sizes are far too small
# for a formal claim regardless). Charging PA a 50% tax to half-satisfy a claim
# the work does not make would only distort the key-management economics that
# ARE the subject of this research.
#
# Set True for the conservative accounting; the QBER-uncertainty section
# measures and reports exactly what it costs, so the choice is quantified rather
# than assumed either way.
PA_USE_QBER_UPPER_BOUND = False

# --- ITEM 22: finite-key security parameters, defined once ---------------
# Privacy amplification previously computed a compression ratio with no stated
# security parameters at all - there was no epsilon anywhere in the notebook, so
# "secret key" had no quantitative meaning. These are the standard parameters of
# a composable finite-key security definition:
EPS_SECRECY = 1e-10      # eps_sec: max distinguishing advantage between the key
                         #   and a uniform string that is independent of Eve
EPS_CORRECTNESS = 1e-15  # eps_cor: max probability Alice's and Bob's keys differ
EPS_PA = 1e-10           # eps_PA: smoothing parameter of the leftover hash lemma
# Total composable security parameter of one session's key.
EPS_TOTAL = EPS_SECRECY + EPS_CORRECTNESS + EPS_PA


def default_usage_policy(key_bits):
    """Advisory policy delivered alongside every application key."""
    alg = {128: 'AES-128-GCM', 192: 'AES-192-GCM', 256: 'AES-256-GCM'}.get(
        int(key_bits), f'AES-{int(key_bits)}-GCM')
    return {'algorithm': alg,
            'mode': 'AEAD',
            'max_bytes': 2 ** 38,          # NIST SP 800-38D limit for one GCM key
            'max_seconds': KEY_TTL_SEC,
            'single_use_per_peer': True,
            'reuse_after_expiry': False}


# ===================================================================
# notebook cell [8] -> alice
#   provides: Alice
# ===================================================================
class Alice:
    """Sender in BB84. Generates random bits/bases and encodes qubits."""

    def __init__(self, n_bits, rng):
        self.n_bits = n_bits
        self.rng = rng
        self.bits = None
        self.bases = None  # 0 = rectilinear (+), 1 = diagonal (x)

    def generate_random_bits(self, verbose=False):
        self.bits = self.rng.integers(0, 2, self.n_bits)
        if verbose:
            print(f"Alice's bits (first 20):    {self.bits[:20]}")
        return self.bits

    def generate_random_bases(self, verbose=False):
        self.bases = self.rng.integers(0, 2, self.n_bits)
        if verbose:
            print(f"Alice's bases (first 20):   {self.bases[:20]}  (0=+, 1=x)")
        return self.bases

    def encode_photons(self, verbose=False):
        """Return one QuantumCircuit per photon (no measurement yet)."""
        circuits = []
        for i in range(self.n_bits):
            qc = QuantumCircuit(1, 1)
            if self.bits[i] == 1:
                qc.x(0)          # |0> -> |1>
            if self.bases[i] == 1:
                qc.h(0)          # rectilinear -> diagonal
            circuits.append(qc)
        if verbose:
            print(f"{self.n_bits} photons encoded by Alice")
        return circuits


# ===================================================================
# notebook cell [10] -> channel
#   provides: QuantumChannel (depolarising noise, Eve intercept-resend, loss)
# ===================================================================
class QuantumChannel:
    """Quantum transmission with a real depolarizing channel and optional Eve.

    error_rate:         probability a depolarizing error (random X/Y/Z) hits a photon
    eve_intercept_rate: fraction of photons Eve intercept-resends (0.0 = no Eve)
    loss_rate:          fraction of photons that never reach Bob (0.0 = lossless)

    Fix (2026-09-12, NO LOSS TO SWEEP): `loss_rate` was added so photon loss can
    be swept in the robustness section. It is DEFAULT 0.0, so no existing result
    changes. Loss is modelled at the only place it is observable in this
    architecture: a lost photon produces no detection at Bob, so that position
    is dropped during basis reconciliation and never enters the sifted key.
    `arrived_mask` records which photons survived.

    What this does and does not model - state it plainly rather than implying a
    physical-layer channel exists:
      - It DOES capture loss's real consequence for this framework: a shorter
        sifted key means a smaller QBER sample, which means a WIDER confidence
        interval and a less trustworthy abort decision. Loss degrades detection
        CONFIDENCE without itself raising QBER.
      - It does NOT derive the loss from a fibre length or an attenuation
        coefficient; loss is a free parameter, not 0.2 dB/km over a distance.
      - It does NOT model detector efficiency, dark counts, misalignment,
        multi-photon pulses or decoy states. Those remain unmodelled (see
        Research Boundary), and in particular a fibre-tap attacker who hides
        inside the loss is still OUT OF SCOPE: this models the loss, not an
        adversary exploiting it.
    """

    def __init__(self, error_rate=0.0, eve_intercept_rate=0.0, loss_rate=0.0,
                 rng=None, seed=SEED):
        self.error_rate = error_rate
        self.eve_intercept_rate = eve_intercept_rate
        self.loss_rate = float(loss_rate)
        self.rng = rng if rng is not None else make_rng(seed)
        self.seed = seed
        self.sim = AerSimulator()
        self.arrived_mask = None

    def _apply_depolarizing(self, qc):
        """With prob error_rate, apply a uniformly random Pauli (X, Y or Z)."""
        if self.rng.random() < self.error_rate:
            pauli = self.rng.integers(0, 3)  # 0->X, 1->Y, 2->Z
            if pauli == 0:
                qc.x(0)
            elif pauli == 1:
                qc.y(0)
            else:
                qc.z(0)
        return qc

    def transmit(self, circuits, verbose=False):
        n = len(circuits)
        # Decide which photons Eve touches up front so we can batch her jobs.
        eve_mask = self.rng.random(n) < self.eve_intercept_rate
        eve_bases = self.rng.integers(0, 2, n)

        # --- Batch Eve's measurement circuits (Fix #17) ---
        eve_indices = np.nonzero(eve_mask)[0]
        eve_results = {}
        if len(eve_indices) > 0:
            eve_circuits = []
            for idx in eve_indices:
                mqc = circuits[idx].copy()
                if eve_bases[idx] == 1:
                    mqc.h(0)
                mqc.measure(0, 0)
                eve_circuits.append(mqc)
            job = self.sim.run(eve_circuits, shots=1, seed_simulator=self.seed)
            counts_list = job.result().get_counts()
            if isinstance(counts_list, dict):
                counts_list = [counts_list]
            for pos, idx in enumerate(eve_indices):
                eve_results[idx] = int(list(counts_list[pos].keys())[0])

        # --- Build the transmitted circuits ---
        transmitted = []
        for i, qc in enumerate(circuits):
            if eve_mask[i]:
                # Eve resends a fresh state prepared from what she measured.
                new_qc = QuantumCircuit(1, 1)
                if eve_results[i] == 1:
                    new_qc.x(0)
                if eve_bases[i] == 1:
                    new_qc.h(0)
                qc_out = new_qc
            else:
                qc_out = qc.copy()
            qc_out = self._apply_depolarizing(qc_out)
            transmitted.append(qc_out)

        # Photon loss: decided here, applied at basis reconciliation (a lost
        # photon simply produces no detection at Bob).
        if self.loss_rate > 0.0:
            self.arrived_mask = self.rng.random(n) >= self.loss_rate
        else:
            self.arrived_mask = np.ones(n, dtype=bool)

        if verbose:
            _lost = int(n - np.sum(self.arrived_mask))
            print(f"{n} photons transmitted | noise={self.error_rate*100:.1f}% "
                  f"| eve={self.eve_intercept_rate*100:.1f}%"
                  + (f" | loss={self.loss_rate*100:.1f}% ({_lost} lost)"
                     if self.loss_rate > 0 else ""))
        return transmitted


# ===================================================================
# notebook cell [12] -> bob
#   provides: Bob
# ===================================================================
class Bob:
    """Receiver in BB84. Measures incoming photons in randomly chosen bases."""

    def __init__(self, n_bits, rng, seed=SEED):
        self.n_bits = n_bits
        self.rng = rng
        self.seed = seed
        self.bases = None
        self.measurements = None
        self.sim = AerSimulator()

    def generate_random_bases(self, verbose=False):
        self.bases = self.rng.integers(0, 2, self.n_bits)
        if verbose:
            print(f"Bob's bases (first 20):     {self.bases[:20]}  (0=+, 1=x)")
        return self.bases

    def measure_photons(self, circuits, verbose=False):
        meas_circuits = []
        for i, qc in enumerate(circuits):
            qc_copy = qc.copy()
            if self.bases[i] == 1:
                qc_copy.h(0)
            qc_copy.measure(0, 0)
            meas_circuits.append(qc_copy)

        # Single batched job for all photons (Fix #17), seeded (Fix #16).
        job = self.sim.run(meas_circuits, shots=1, seed_simulator=self.seed)
        counts_list = job.result().get_counts()
        if isinstance(counts_list, dict):
            counts_list = [counts_list]
        measurements = [int(list(c.keys())[0]) for c in counts_list]

        self.measurements = np.array(measurements)
        if verbose:
            print(f"{len(measurements)} photons measured by Bob")
        return self.measurements


# ===================================================================
# notebook cell [14] -> sifting
#   provides: BB84KeySifting
# ===================================================================
class BB84KeySifting:
    """Basis reconciliation + key sifting over the (public) classical channel."""

    @staticmethod
    def basis_reconciliation(alice_bases, bob_bases, arrived=None, verbose=False):
        """Keep positions where the bases agree AND Bob actually detected.

        `arrived` (2026-09-12) is the channel's photon-arrival mask. A lost
        photon gives Bob no detection, so Bob publicly reports which slots he
        detected in and both sides drop the rest - standard practice, and no
        extra information is leaked because arrival is independent of the bit
        value. Defaults to all-arrived, so lossless behaviour is unchanged.
        """
        matching = alice_bases == bob_bases
        if arrived is not None:
            matching = matching & np.asarray(arrived, dtype=bool)
        if verbose:
            m = int(np.sum(matching)); t = len(alice_bases)
            lost = '' if arrived is None else \
                f", {int(t - np.sum(arrived))} lost in the channel"
            print(f"Basis reconciliation: {m}/{t} kept ({m/t*100:.1f}%{lost})")
        return matching

    @staticmethod
    def key_sifting(alice_bits, bob_measurements, matching_indices, verbose=False):
        alice_sifted = alice_bits[matching_indices]
        bob_sifted = bob_measurements[matching_indices]
        if verbose:
            print(f"Raw sifted key length: {len(alice_sifted)} bits")
        return alice_sifted, bob_sifted


# ===================================================================
# notebook cell [16] -> auth
#   provides: AuthenticationError, AuthKeyReserve, toeplitz_tag, AuthenticatedClassicalChannel
# ===================================================================
# --- Classical-channel authentication: Wegman-Carter, wired into the protocol
import hmac


class AuthenticationError(RuntimeError):
    """Raised when a public message fails its Wegman-Carter tag check."""


class AuthKeyReserve:
    """The pre-shared authentication key, and its replenishment from QKD output.

    ITEM 17 (bootstrapping): BB84 cannot authenticate its own first message.
    Alice and Bob MUST begin with a short pre-shared secret established out of
    band - physically exchanged, couriered, or delivered over a prior secure
    channel. That is what `initial_bits` models. It is NOT produced by QKD, and
    labelling it clearly is the difference between describing QKD as key
    EXPANSION (correct) and key GENERATION from nothing (not what BB84 does).

    Each session then reserves part of its own output to authenticate the next
    one, so the link is self-sustaining as long as it produces more key than it
    spends on authentication.
    """

    def __init__(self, initial_bits=None, target_bits=None, rng=None, seed=SEED):
        rng = rng if rng is not None else make_rng(seed)
        self.bootstrap_bits = int(AUTH_BOOTSTRAP_BITS if initial_bits is None
                                  else initial_bits)
        # Pre-shared, out-of-band. Drawn from the simulation PRNG here; in a
        # deployment this is physical key material (see crypto_rng()).
        self.bits = list(rng.integers(0, 2, self.bootstrap_bits).tolist())
        self.target_bits = int(target_bits if target_bits is not None
                               else self.bootstrap_bits)
        self.consumed = 0
        self.replenished = 0
        self.operational_delivered = 0
        self.exhaustion_events = 0

    def available(self):
        return len(self.bits)

    def consume(self, n_bits):
        """Take n_bits of authentication key. Returns None if the reserve is
        short - which means the link can no longer authenticate."""
        n = int(n_bits)
        if len(self.bits) < n:
            self.exhaustion_events += 1
            return None
        out = np.array(self.bits[:n], dtype=np.uint8)
        del self.bits[:n]
        self.consumed += n
        return out

    def deficit(self):
        return max(0, self.target_bits - len(self.bits))

    def replenish(self, key_bits):
        """Top the reserve back up to target from a session's output.
        Returns (bits_taken, remainder) - the remainder is what may go to the
        operational key pool. Authentication is paid FIRST, deliberately: a link
        that spends its last bits on payload keys can never talk again."""
        need = self.deficit()
        if need <= 0 or len(key_bits) == 0:
            self.operational_delivered += len(key_bits)
            return 0, np.asarray(key_bits)
        take = min(need, len(key_bits))
        self.bits.extend(np.asarray(key_bits[:take], dtype=np.uint8).tolist())
        self.replenished += take
        rest = np.asarray(key_bits[take:])
        self.operational_delivered += len(rest)
        return take, rest

    def expansion_factor(self):
        """Operational bits delivered per bootstrap bit - the honest statement
        of what the link actually achieved."""
        return self.operational_delivered / max(1, self.bootstrap_bits)

    def status(self):
        return {'bootstrap_bits': self.bootstrap_bits,
                'available_bits': self.available(),
                'consumed_bits': self.consumed,
                'replenished_bits': self.replenished,
                'operational_bits_delivered': self.operational_delivered,
                'expansion_factor': round(self.expansion_factor(), 2),
                'exhaustion_events': self.exhaustion_events}


def toeplitz_tag(message_bits, out_len, seed):
    """Toeplitz universal hash of message_bits down to out_len bits.

    Self-contained (no dependency on PrivacyAmplification, which is defined
    later) so authentication can be used from the first protocol message.
    """
    msg = np.asarray(message_bits, dtype=np.int64).ravel()
    n = len(msg)
    if n == 0 or out_len <= 0:
        return np.zeros(max(0, out_len), dtype=np.uint8)
    rand_bits = make_rng(int(seed)).integers(0, 2, size=n + out_len - 1)
    out = np.empty(out_len, dtype=np.uint8)
    for i in range(out_len):
        out[i] = int(np.dot(rand_bits[i:i + n], msg) % 2)
    return out


def _to_bits(obj):
    """Serialise anything the protocol sends into a bit array."""
    if isinstance(obj, (bytes, bytearray)):
        return np.unpackbits(np.frombuffer(bytes(obj), dtype=np.uint8))
    arr = np.asarray(obj)
    if arr.dtype == bool:
        arr = arr.astype(np.uint8)
    if arr.dtype.kind in 'iu' and arr.max(initial=0) <= 1 and arr.min(initial=0) >= 0:
        return arr.astype(np.uint8).ravel()
    return np.unpackbits(np.ascontiguousarray(arr).view(np.uint8))


class AuthenticatedClassicalChannel:
    """Wegman-Carter authenticated public channel.

    tag = ToeplitzHash(message) XOR one_time_pad

    The Toeplitz hash key is pre-shared and REUSED across messages; only the
    one-time pad must be fresh. That is the standard Wegman-Carter key-recycling
    argument, and it is why authenticating a message costs AUTH_TAG_BITS rather
    than a full fresh hash key.

    Every send() draws AUTH_TAG_BITS from the AuthKeyReserve. receive() rejects
    any message whose tag does not verify, raising AuthenticationError - which
    the session runner turns into an abort.
    """

    def __init__(self, reserve, tag_bits=None, hash_seed=None, mode=None,
                 rng=None, seed=SEED):
        self.reserve = reserve
        self.tag_bits = int(AUTH_TAG_BITS if tag_bits is None else tag_bits)
        self.mode = AUTH_MODE if mode is None else mode
        rng = rng if rng is not None else make_rng(seed)
        # Pre-shared Toeplitz hash key (part of the bootstrap material).
        self.hash_seed = int(hash_seed if hash_seed is not None
                             else rng.integers(0, 2 ** 62))
        self.messages_sent = 0
        self.tags_issued = 0          # tags actually computed (= reserve draws)
        self.messages_rejected = 0
        self.bits_consumed = 0
        self.log = []
        self._sent = []                # Alice's transcript (mode='transcript')
        self._recv = []                # what Bob actually received

    # ---------- core WC operations ----------
    def _tag(self, msg_bits, pad):
        h = toeplitz_tag(msg_bits, self.tag_bits, self.hash_seed)
        return np.bitwise_xor(h, pad.astype(np.uint8))

    def begin_session(self):
        """Clear the transcript buffers. Called at the start of every session so
        one session's messages can never be authenticated as another's."""
        self._sent = []
        self._recv = []

    def send(self, label, payload):
        """Authenticate and 'transmit' one public message.
        Returns the wire message, or raises AuthenticationError if the reserve
        is exhausted (the link can no longer authenticate at all)."""
        bits = _to_bits(payload)
        if self.mode == 'transcript':
            # Delayed authentication: Alice records what she SENT; the tag over
            # the whole transcript is computed and compared at close().
            self._sent.append(bits)
            self.messages_sent += 1
            return {'label': label, 'bits': bits, 'tag': None, 'deferred': True}
        pad = self.reserve.consume(self.tag_bits)
        if pad is None:
            raise AuthenticationError(
                f'authentication key reserve EXHAUSTED before sending {label!r} '
                f'({self.reserve.available()} bits left, {self.tag_bits} needed). '
                'The link cannot authenticate and must stop.')
        self.bits_consumed += self.tag_bits
        self.messages_sent += 1
        self.tags_issued += 1
        tag = self._tag(bits, pad)
        self.log.append({'label': label, 'bits_len': int(len(bits)),
                         'tag_bits': self.tag_bits})
        return {'label': label, 'bits': bits, 'tag': tag, 'pad': pad,
                'deferred': False}

    def receive(self, message, tamper=False):
        """Verify a message's tag. Returns its payload bits, or raises.
        `tamper=True` flips one bit in transit - used by tamper_test()."""
        if message.get('deferred'):
            # Transcript mode: Bob records what he RECEIVED (tampering and all).
            # The mismatch surfaces at close(), which is what delayed
            # authentication means - the session is still aborted, just at the
            # end rather than mid-protocol.
            bits = message['bits'].copy()
            if tamper and len(bits):
                bits[0] ^= 1
            self._recv.append(bits)
            return bits
        bits = message['bits'].copy()
        if tamper and len(bits):
            bits[0] ^= 1
        expected = self._tag(bits, message['pad'])
        if not hmac.compare_digest(expected.tobytes(), message['tag'].tobytes()):
            self.messages_rejected += 1
            raise AuthenticationError(
                f'classical-channel authentication FAILED on {message["label"]!r}: '
                'the message was altered in transit (possible man-in-the-middle). '
                'Session must abort - BB84 offers no security over an '
                'unauthenticated channel.')
        return bits

    def exchange(self, label, payload, tamper=False):
        """send() + receive() as one call - what the protocol actually does."""
        return self.receive(self.send(label, payload), tamper=tamper)

    def close(self):
        """mode='transcript': authenticate the whole session transcript at once.

        Deployment-style DELAYED authentication: one tag per session rather than
        one per phase, covering exactly the same four messages. Alice tags the
        transcript she sent; Bob tags the transcript he received; a mismatch
        anywhere in the session - basis announcement, QBER sample, Cascade
        parities or the verification tag - makes the two differ and aborts the
        session. The only thing given up versus per-phase tagging is WHEN the
        abort happens, not WHETHER it happens.

        Raises AuthenticationError on mismatch; returns True on success.
        """
        if self.mode != 'transcript' or not self._sent:
            return True
        sent_bits = np.concatenate(self._sent)
        recv_bits = np.concatenate(self._recv) if self._recv else np.array([], np.uint8)
        pad = self.reserve.consume(self.tag_bits)
        if pad is None:
            raise AuthenticationError(
                'authentication key reserve EXHAUSTED at transcript close.')
        self.bits_consumed += self.tag_bits
        self.tags_issued += 1
        alice_tag = self._tag(sent_bits, pad)
        bob_tag = (self._tag(recv_bits, pad) if len(recv_bits) == len(sent_bits)
                   else np.bitwise_not(alice_tag))   # length change = tampering
        self.begin_session()
        if not hmac.compare_digest(alice_tag.tobytes(), bob_tag.tobytes()):
            self.messages_rejected += 1
            raise AuthenticationError(
                'classical-channel authentication FAILED on the session '
                'transcript: at least one public message was altered in transit '
                '(possible man-in-the-middle). Session must abort - BB84 offers '
                'no security over an unauthenticated channel.')
        return True

    def tamper_test(self):
        """Prove the rejection path fires: authenticate a message, alter it in
        transit, and confirm the alteration is caught - immediately in per-phase
        mode, at close() in transcript mode."""
        self.begin_session()
        msg = self.send('tamper_probe', np.array([1, 0, 1, 1, 0, 0, 1, 0]))
        try:
            self.receive(msg, tamper=True)
            self.close()
            return False
        except AuthenticationError:
            self.begin_session()
            return True

    def status(self):
        return {'mode': self.mode, 'tag_bits': self.tag_bits,
                'messages_authenticated': self.messages_sent,
                'tags_issued': self.tags_issued,
                'messages_rejected': self.messages_rejected,
                'auth_bits_consumed': self.bits_consumed}


# ===================================================================
# notebook cell [18] -> qber
#   provides: QBERCalculator (point estimate + one-sided upper bound)
# ===================================================================
class QBERCalculator:
    """Estimate QBER by publicly sacrificing a random sample of sifted bits.

    Fix (2026-09-12, POINT ESTIMATE USED AS IF IT WERE THE TRUTH): the previous
    version computed `qber = errors / sample_size` and compared that single
    number against 0.11. With a 25% sample of a ~375-bit sifted key the sample is
    only ~90 bits, so observing 2 errors gives a point estimate of 2.2% whose
    exact 99% upper confidence bound is above 9% - i.e. a session that "passed"
    at 2.2% was statistically consistent with an error rate a factor of four
    higher. Sampling uncertainty was invisible: the sample size was never
    recorded, no interval was computed, and the abort decision ignored both.

    What changed:
      1. `sample_size` and `errors` are recorded and exported as telemetry.
      2. A one-sided upper confidence bound is computed (Clopper-Pearson exact
         binomial; Hoeffding fallback if SciPy is unavailable).
      3. The ABORT DECISION uses the upper bound, not the point estimate. This
         is the conservative direction: a session is accepted only if the true
         error rate is below threshold at the stated confidence.
      4. `sample_fraction` is a swept parameter (see the QBER-uncertainty
         section) rather than an unexamined default.

    The point estimate is still what gets exported as the `qber` FEATURE, because
    that is what an operator actually observes per session; the bound is what
    gates security. Keeping those two roles separate is deliberate.
    """

    # --- ASSUMPTION, not a derived result -------------------------------
    # 0.11 is the ASYMPTOTIC Shor-Preskill bound for BB84 with one-way
    # reconciliation, valid in the limit of infinitely long keys. This notebook's
    # keys are finite (hundreds of bits), where the true tolerable error rate is
    # LOWER and depends on key length and on the security parameters. 0.11 is
    # retained here as a SIMPLIFIED SIMULATION THRESHOLD so that results stay
    # comparable with the wider BB84 literature - it is NOT a security claim
    # about the keys this notebook produces. Any security claim must go through
    # the finite-key bound in the QBER-uncertainty section instead.
    SECURITY_THRESHOLD = 0.11           # assumption; see above
    DEFAULT_CONFIDENCE = 0.99           # one-sided confidence for the abort bound
    USE_UPPER_BOUND = True              # decide on the bound, not the point estimate

    @staticmethod
    def upper_confidence_bound(errors, sample_size, confidence=None):
        """One-sided upper confidence bound on the true bit-error rate given
        `errors` out of `sample_size` sampled bits.

        Clopper-Pearson (exact binomial) is used when SciPy is available:
            e_upper = BetaInv(confidence; errors + 1, sample_size - errors)
        It is conservative by construction, which is the right direction for a
        security decision. Hoeffding's bound is the fallback:
            e_upper = e_hat + sqrt(ln(1/(1-confidence)) / (2 * sample_size))
        """
        conf = QBERCalculator.DEFAULT_CONFIDENCE if confidence is None else confidence
        n = int(sample_size)
        k = int(errors)
        if n <= 0:
            return 1.0
        if k >= n:
            return 1.0
        try:
            from scipy import stats as _st
            return float(_st.beta.ppf(conf, k + 1, n - k))
        except Exception:
            slack = float(np.sqrt(np.log(1.0 / max(1e-12, 1.0 - conf)) / (2.0 * n)))
            return float(min(1.0, k / n + slack))

    @staticmethod
    def calculate(alice_sifted, bob_sifted, rng, sample_fraction=0.25,
                  confidence=None, use_upper_bound=None, detail=None,
                  verbose=False):
        """Returns (qber_point, secure, alice_remaining, bob_remaining).

        `secure` is decided on the UPPER CONFIDENCE BOUND when
        use_upper_bound is True (default). Pass a dict as `detail` to receive the
        full estimate - point value, bound, sample size, errors, confidence - for
        telemetry and auditing, without changing this method's return signature.
        """
        conf = QBERCalculator.DEFAULT_CONFIDENCE if confidence is None else confidence
        use_ub = QBERCalculator.USE_UPPER_BOUND if use_upper_bound is None else use_upper_bound

        n = len(alice_sifted)
        if n == 0:
            if detail is not None:
                detail.update({'qber_point': 0.0, 'qber_upper': 1.0,
                               'qber_sample_size': 0, 'qber_errors': 0,
                               'qber_sample_fraction': float(sample_fraction),
                               'qber_confidence': conf, 'qber_decision_basis': 'empty',
                               'qber_ci_width': float('nan')})
            return 0.0, False, np.array([]), np.array([])

        sample_size = max(1, int(n * sample_fraction))
        sample_indices = rng.choice(n, sample_size, replace=False)

        errors = int(np.sum(alice_sifted[sample_indices] != bob_sifted[sample_indices]))
        qber = errors / sample_size
        qber_upper = QBERCalculator.upper_confidence_bound(errors, sample_size, conf)

        remaining_mask = np.ones(n, dtype=bool)
        remaining_mask[sample_indices] = False
        alice_remaining = alice_sifted[remaining_mask]
        bob_remaining = bob_sifted[remaining_mask]

        decision_value = qber_upper if use_ub else qber
        secure = decision_value <= QBERCalculator.SECURITY_THRESHOLD

        if detail is not None:
            detail.update({
                'qber_point': float(qber),
                'qber_upper': float(qber_upper),
                'qber_sample_size': int(sample_size),
                'qber_errors': int(errors),
                'qber_sifted_len': int(n),
                'qber_sample_fraction': float(sample_fraction),
                'qber_confidence': float(conf),
                'qber_ci_width': float(qber_upper - qber),
                'qber_decision_basis': 'upper_bound' if use_ub else 'point_estimate',
            })

        if verbose:
            status = 'secure' if secure else 'ABORT (possible eavesdropping)'
            basis = 'upper bound' if use_ub else 'point estimate'
            print(f"QBER: {qber*100:.2f}% ({errors}/{sample_size} sampled bits) | "
                  f"{conf*100:.0f}% upper bound {qber_upper*100:.2f}% | "
                  f"decision on {basis} vs {QBERCalculator.SECURITY_THRESHOLD*100:.0f}% "
                  f"-> {status}")
        return qber, secure, alice_remaining, bob_remaining


# ===================================================================
# notebook cell [20] -> ec
#   provides: ErrorCorrection (Cascade with look-back)
# ===================================================================
class ErrorCorrection:
    """Cascade reconciliation (Brassard-Salvail): multiple shuffled passes,
    binary-search localisation, block-size doubling, and LOOK-BACK.

    Fix (2026-09-12, ITEM 20): look-back was missing, which is the feature
    Cascade is named for. It is implemented here; BICONF and the optimised
    block-size schedules of later variants are NOT, and that boundary is stated
    rather than blurred.
    """

    @staticmethod
    def _parity(bits):
        return int(np.sum(bits) % 2)

    @staticmethod
    def _compare_parity(alice_key, bob_key, idx, leak_counter, transcript=None):
        """One public parity comparison. Returns True if the parities DIFFER.
        Every call discloses one bit and is counted."""
        a_par = ErrorCorrection._parity(alice_key[idx])
        b_par = ErrorCorrection._parity(bob_key[idx])
        leak_counter[0] += 1
        if transcript is not None:
            transcript.append(a_par); transcript.append(b_par)
        return a_par != b_par

    @staticmethod
    def _binary_search_correct(alice_key, bob_key, idx_list, leak_counter,
                               transcript=None):
        """Given a block known to contain an ODD number of errors, binary-search
        for one erroneous position and flip it in bob_key. Returns the position."""
        idx_list = list(idx_list)
        while len(idx_list) > 1:
            mid = len(idx_list) // 2
            left = idx_list[:mid]
            if ErrorCorrection._compare_parity(alice_key, bob_key, left,
                                               leak_counter, transcript):
                idx_list = left            # odd # of errors is in the left half
            else:
                idx_list = idx_list[mid:]  # ...otherwise in the right half
        pos = idx_list[0]
        bob_key[pos] ^= 1
        return pos

    @staticmethod
    def initial_block_size(qber_estimate, fallback=8):
        """Standard Cascade heuristic k1 ~ 0.73 / QBER, clamped to something
        sane. Uses the QBER the protocol has already estimated - no extra
        disclosure, since that estimate is public already."""
        if not qber_estimate or qber_estimate <= 0:
            return fallback
        return int(np.clip(round(0.73 / qber_estimate), 4, 64))

    @staticmethod
    def correct(alice_key, bob_key, rng, block_size=None, n_passes=4,
                verbose=False, transcript=None, stats=None, qber_estimate=None,
                use_lookback=True, adaptive_block_size=True):
        """Cascade reconciliation.

        Returns (corrected_bob, alice_key, parity_leaked).

        `transcript`: list to capture every parity bit exchanged, so the session
            runner can authenticate the reconciliation messages (see the
            Wegman-Carter channel).
        `stats`: dict to receive the efficiency report (ITEM 21) - errors before
            and after, parity bits disclosed, reconciliation efficiency f, and
            the Shannon lower bound the leak is measured against.
        `use_lookback`: Cascade's defining behaviour. After each correction, the
            blocks of every OTHER pass containing that position are re-checked;
            a parity that now differs means another error, found cheaply.
        """
        alice_key = np.array(alice_key, dtype=int).copy()
        corrected = np.array(bob_key, dtype=int).copy()
        n = len(alice_key)
        if n == 0:
            if stats is not None:
                stats.update({'ec_errors_before': 0, 'ec_errors_after': 0,
                              'ec_parity_disclosed': 0, 'ec_efficiency_f': float('nan'),
                              'ec_shannon_bound': 0.0, 'ec_corrections': 0,
                              'ec_lookback_corrections': 0, 'ec_initial_block': 0})
            return corrected, alice_key, 0

        leak_counter = [0]
        errors_before = int(np.sum(alice_key != corrected))

        bs = (ErrorCorrection.initial_block_size(qber_estimate)
              if adaptive_block_size else (block_size or 8))
        initial_bs = bs

        pass_blocks = []     # per pass: list of index arrays
        pos_to_block = []    # per pass: position -> block index
        n_corrections = 0
        n_lookback = 0

        for p in range(n_passes):
            perm = np.arange(n) if p == 0 else rng.permutation(n)
            blocks = [perm[s:s + bs] for s in range(0, n, bs)]
            pb = np.empty(n, dtype=int)
            for bi, blk in enumerate(blocks):
                pb[blk] = bi
            pass_blocks.append(blocks)
            pos_to_block.append(pb)

            # Top-level parity check over this pass's blocks.
            queue = [(p, bi) for bi in range(len(blocks))]
            while queue:
                pj, bi = queue.pop()
                blk = pass_blocks[pj][bi]
                if len(blk) == 0:
                    continue
                if not ErrorCorrection._compare_parity(alice_key, corrected, blk,
                                                       leak_counter, transcript):
                    continue                      # parities agree - nothing to do
                pos = ErrorCorrection._binary_search_correct(
                    alice_key, corrected, blk, leak_counter, transcript)
                n_corrections += 1
                if use_lookback:
                    # THE CASCADE STEP: this correction flips the parity of the
                    # block containing `pos` in every other pass, so each of
                    # those blocks now holds an odd number of errors.
                    for j in range(len(pass_blocks)):
                        if j == pj:
                            continue
                        queue.append((j, int(pos_to_block[j][pos])))
                        n_lookback += 1
            bs = max(2, bs * 2)          # Cascade doubles the block size

        remaining = int(np.sum(alice_key != corrected))
        leak = leak_counter[0]

        # ITEM 21: reconciliation efficiency. The Shannon lower bound on the
        # information any reconciliation protocol must disclose to correct a
        # binary symmetric channel at error rate e over n bits is n*h(e).
        # f = leak / (n*h(e)); f = 1.0 is the theoretical limit, and practical
        # Cascade implementations report f ~ 1.1-1.3. f < 1 would mean the
        # protocol disclosed LESS than the Shannon bound, which is impossible -
        # if it appears, the leak counter is wrong.
        e_obs = (errors_before / n) if n else 0.0
        h_e = PrivacyAmplification._binary_entropy(e_obs) if 0 < e_obs < 1 else 0.0
        shannon = n * h_e
        f_eff = (leak / shannon) if shannon > 0 else float('nan')

        if stats is not None:
            stats.update({
                'ec_block_len': int(n),
                'ec_errors_before': errors_before,
                'ec_errors_after': remaining,
                'ec_error_rate_before': e_obs,
                'ec_parity_disclosed': int(leak),
                'ec_shannon_bound': float(shannon),
                'ec_efficiency_f': float(f_eff),
                'ec_corrections': int(n_corrections),
                'ec_lookback_checks': int(n_lookback),
                'ec_initial_block': int(initial_bs),
                'ec_lookback_enabled': bool(use_lookback),
            })

        if verbose:
            print(f"Error correction: {errors_before} -> {remaining} errors, "
                  f"{leak} parity bits disclosed "
                  f"(k1={initial_bs}, f={f_eff:.2f} vs Shannon bound "
                  f"{shannon:.0f} bits, lookback={'on' if use_lookback else 'off'})")
        return corrected, alice_key, leak


# ===================================================================
# notebook cell [22] -> verify
#   provides: key_verification_tag, keys_agree
# ===================================================================
def key_verification_tag(key_bits, seed, tag_bits=None):
    """Short universal-hash verification tag for a reconciled key.

    ITEM 18: this replaces a full SHA-256 digest. Two reasons, stated plainly:

    1. LENGTH. A SHA-256 digest is 256 bits - frequently LONGER than the
       reconciled key it verifies (a 112-bit key was being represented by a
       256-bit public value), and privacy amplification never subtracted any of
       it. The secret-bit budget was overstated by the full digest length in
       every single session.
    2. FAMILY. SHA-256 is one fixed function, not a universal hash family, so it
       carries no clean collision bound against an adversarially chosen pair. A
       Toeplitz universal family keyed by a fresh public seed per session does:
       two DISTINCT keys collide with probability at most 2^-tag_bits.

    With the default tag_bits = 32 the verification-failure probability - the
    chance a session with residual errors is wrongly accepted - is
    2^-32 ~ 2.3e-10. That is now a stated design parameter, not an assumption.
    """
    tb = int(VERIFY_TAG_BITS if tag_bits is None else tag_bits)
    return toeplitz_tag(np.asarray(key_bits, dtype=np.int64), tb, seed)


def keys_agree(alice_key, bob_key, seed=None, tag_bits=None, rng=None):
    """Publicly verify agreement with a short universal-hash tag.

    Returns (agree, disclosed_bits). `disclosed_bits` is what privacy
    amplification must subtract - the tag is public, so it is leakage, and it is
    now accounted for instead of being silently free.
    """
    tb = int(VERIFY_TAG_BITS if tag_bits is None else tag_bits)
    if len(alice_key) != len(bob_key) or len(alice_key) == 0:
        return False, 0
    if seed is None:
        seed = int((rng or make_rng()).integers(0, 2 ** 62))
    ta = key_verification_tag(alice_key, seed, tb)
    tb_ = key_verification_tag(bob_key, seed, tb)
    return bool(np.array_equal(ta, tb_)), tb


VERIFICATION_FAILURE_PROBABILITY = 2.0 ** (-VERIFY_TAG_BITS)


# ===================================================================
# notebook cell [24] -> pa
#   provides: PrivacyAmplification (Toeplitz universal hashing)
# ===================================================================
class PrivacyAmplification:
    """Privacy amplification via a random Toeplitz universal hash."""

    @staticmethod
    def security_parameters():
        """ITEM 22: the composable security parameters this extraction claims."""
        return {'eps_secrecy': EPS_SECRECY, 'eps_correctness': EPS_CORRECTNESS,
                'eps_privacy_amplification': EPS_PA, 'eps_total': EPS_TOTAL,
                'note': ('Asymptotic extraction by default. The finite-key '
                         'statistical correction is reported in the QBER '
                         'uncertainty section, not applied here.')}

    @staticmethod
    def _binary_entropy(x):
        if x <= 0 or x >= 1:
            return 0.0
        return float(-x * np.log2(x) - (1 - x) * np.log2(1 - x))

    @staticmethod
    def _toeplitz_hash(key_bits, out_len, seed_rng):
        """Multiply an (out_len x n) random Toeplitz matrix by key_bits mod 2.
        A Toeplitz matrix is fully specified by its first row + first column,
        i.e. (n + out_len - 1) public random bits."""
        n = len(key_bits)
        rand_bits = seed_rng.integers(0, 2, size=n + out_len - 1)
        key = np.array(key_bits, dtype=int)
        out = np.empty(out_len, dtype=int)
        # Row i uses rand_bits[i : i+n] as the Toeplitz row.
        for i in range(out_len):
            row = rand_bits[i:i + n]
            out[i] = int(np.dot(row, key) % 2)
        return out

    @staticmethod
    def amplify(key_bits, qber, parity_bits_leaked, rng, qber_upper=None,
                disclosed_bits=0, stats=None, verbose=False):
        """Compress the reconciled key to its secret content.

        Fix (2026-09-12, POINT ESTIMATE IN THE ENTROPY TERM): `qber` here is a
        SAMPLE estimate, not the true error rate. Subtracting h(point estimate)
        assumes the sample was exactly right; when it under-reports - which for
        a ~90-bit sample happens often - the output key contains more of Eve's
        information than the accounting admits. When `qber_upper` (the one-sided
        upper confidence bound from QBERCalculator) is supplied and
        PA_USE_QBER_UPPER_BOUND is set, h() is evaluated at the BOUND instead.
        That is the conservative direction and costs real key length; the cost
        is printed rather than hidden.
        """
        n = len(key_bits)
        if n == 0:
            return np.array([], dtype=int)

        # Fix (2026-09-12, ITEM 18): `disclosed_bits` is public leakage that was
        # never subtracted - principally the key-verification tag, which used to
        # be a 256-bit SHA-256 digest published in the clear for keys sometimes
        # shorter than 256 bits. It is now part of the leakage accounting.
        qber_used = qber
        if PA_USE_QBER_UPPER_BOUND and qber_upper is not None:
            qber_used = max(qber, float(qber_upper))
        # ITEM 22: name every term, so the extractable length is an equation
        # rather than a ratio of unexplained numbers.
        eve_info_per_bit = PrivacyAmplification._binary_entropy(qber_used)
        eve_information = n * eve_info_per_bit          # Eve's entropy, bits
        leakage_estimate = int(parity_bits_leaked) + int(disclosed_bits)
        leaked_fraction = leakage_estimate / n
        secret_fraction = max(0.0, 1.0 - eve_info_per_bit - leaked_fraction)
        extractable = n * (1.0 - eve_info_per_bit) - leakage_estimate
        final_length = int(max(0.0, extractable))

        if stats is not None:
            stats.update({
                'pa_block_bits': int(n),
                'pa_qber_used': float(qber_used),
                'pa_eve_information_bits': float(eve_information),
                'pa_leakage_estimate_bits': int(leakage_estimate),
                'pa_extractable_bits': float(extractable),
                'pa_final_key_bits': int(final_length),
                'pa_eps_secrecy': EPS_SECRECY,
                'pa_eps_correctness': EPS_CORRECTNESS,
                'pa_eps_pa': EPS_PA,
                'pa_eps_total': EPS_TOTAL,
                'pa_aborted': bool(final_length <= 0),
            })

        # ITEM 22: explicit abort condition. If the disclosures plus Eve's
        # information exceed the block, there is NO secret key to extract - and
        # the session must be discarded rather than quietly returning a short
        # string that carries none of the security the name implies.
        if final_length <= 0:
            if verbose:
                print(f'PRIVACY AMPLIFICATION ABORT: extractable length '
                      f'{extractable:.1f} <= 0 '
                      f'(block {n}, Eve {eve_information:.1f} bits, '
                      f'leakage {leakage_estimate} bits). No secret key exists '
                      f'in this block; session discarded.')
            return np.array([], dtype=int)

        # Public Toeplitz seed, exchanged over the (authenticated) classical channel.
        pa_seed = int(rng.integers(0, 2**63 - 1))
        seed_rng = make_rng(pa_seed)
        final_key = PrivacyAmplification._toeplitz_hash(key_bits, final_length, seed_rng)

        if verbose:
            _opt = int(n * max(0.0, 1.0 - PrivacyAmplification._binary_entropy(qber)
                               - leaked_fraction))
            print(f"Privacy amplification: {n} -> {final_length} bits "
                  f"(secret_fraction={secret_fraction:.3f}, "
                  f"h evaluated at QBER={qber_used*100:.2f}% "
                  f"[{'upper bound' if qber_used > qber else 'point estimate'}], "
                  f"seed={pa_seed})")
            if qber_used > qber:
                print(f"   cost of the conservative bound: {_opt - final_length} bits "
                      f"({100*(1 - final_length/max(1,_opt)):.0f}% shorter than the "
                      f"optimistic point-estimate accounting)")
        return final_key

# The classical-channel authentication demo now lives in its own section above
# (AuthenticatedClassicalChannel), which is self-contained: it carries its own
# Toeplitz hash so it can authenticate the very first protocol message, before
# this class exists.


# ===================================================================
# notebook cell [26] -> kms
#   provides: KeyStatus, KeyPool, SynchronizedKeyStores, BB84Metrics
# ===================================================================
import threading
import uuid as _uuid


class KeyStatus:
    """ITEM 25: the complete key lifecycle. The previous pool had no state at
    all - an entry either had bits left or it did not - so 'reserved',
    'consumed', 'revoked' and 'destroyed' were indistinguishable from 'missing'.
    """
    GENERATED = 'GENERATED'   # produced by BB84, not yet admitted for use
    AVAILABLE = 'AVAILABLE'   # in the pool, free to reserve
    RESERVED  = 'RESERVED'    # claimed by an in-flight request, not yet delivered
    ACTIVE    = 'ACTIVE'      # delivered and currently protecting traffic
    CONSUMED  = 'CONSUMED'    # all bits spent
    EXPIRED   = 'EXPIRED'     # TTL elapsed before the bits were spent
    REVOKED   = 'REVOKED'     # withdrawn by policy (superseded, compromise)
    DESTROYED = 'DESTROYED'   # bits zeroised, unrecoverable

    TERMINAL = (CONSUMED, EXPIRED, REVOKED, DESTROYED)
    USABLE = (AVAILABLE, RESERVED, ACTIVE)


class KeyPool:
    """Key management store: identified key records, explicit lifecycle states,
    atomic reservation, and secure destruction.

    Fix (2026-09-12, ITEMS 24/25/27/29/30/31/32): the previous version stored
    anonymous dicts of bits. A key had no identifier, so Alice and Bob could not
    refer to the same key; no status, so a consumed key was indistinguishable
    from a destroyed one; no locking, so two concurrent requests could be served
    the same bits; and no destruction, so retired material simply stayed in
    memory. Each entry is now a full KEY RECORD (ITEM 24):

        key_id, endpoint_a, endpoint_b, connection_id, session_id,
        created_at, expires_at, total_bits, remaining_bits, status

    Concurrency (ITEM 27): every mutation holds a lock, reservations are atomic,
    and a repeated `request_id` returns the SAME reservation instead of
    allocating twice - duplicate-request protection for a retried call.
    """

    def __init__(self, max_age_sec=None, endpoint_a='alice', endpoint_b='bob',
                 label='kms'):
        self.pool = []
        self.label = label
        self.endpoint_a = endpoint_a
        self.endpoint_b = endpoint_b
        self.total_bits_generated = 0
        self.total_bits_consumed = 0
        self.spliced_retrievals = 0
        self.splice_segments = 0
        self.sessions_admitted = 0
        self.rejected_insecure = 0
        self.max_age_sec = max_age_sec
        self._counter = 0
        self._lock = threading.RLock()
        self._reservations = {}        # request_id -> reservation record
        self._by_id = {}               # key_id -> record
        # ITEM 32 metrics
        self.requests_total = 0
        self.requests_succeeded = 0
        self.requests_failed = 0
        self.underflow_events = 0
        self.expired_unused_bits = 0
        self.destroyed_bits = 0
        self.delivery_latencies = []

    # ------------------------------------------------------------------
    # The lock is not copyable, and the replay harness deep-copies pools to give
    # every evaluation arm an identical inventory (see fresh_ai_key_pool()).
    # Drop it on copy and recreate it - the copy is a fresh, independently
    # locked store.
    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop('_lock', None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._lock = threading.RLock()

    def _is_live(self, entry, now):
        if entry['status'] not in KeyStatus.USABLE:
            return False
        if entry['expires_at'] is not None and now > entry['expires_at']:
            return False
        return True

    def _expire_due(self, now=None):
        """ITEM 31: move TTL-elapsed records to EXPIRED and count the bits that
        were never used - 'wasted key' is a real operational cost and was
        previously invisible."""
        now = now or time.time()
        n = 0
        for e in self.pool:
            if e['status'] in KeyStatus.USABLE and e['expires_at'] is not None \
                    and now > e['expires_at']:
                self.expired_unused_bits += int(len(e['remaining']))
                e['status'] = KeyStatus.EXPIRED
                e['expired_at'] = now
                n += 1
        return n

    # ------------------------------------------------------------------
    def store_key(self, key_bits, session_id=None, secure=True, verbose=False,
                  connection_id=None, ttl_sec=None, key_id=None):
        """Admit key material. Returns the key_id (ITEM 24).

        SECURITY INVARIANT: retrieve_key() may splice bits from several records
        into one operational key, so the pool must never hold a bit from a
        session that failed QBER or key verification. secure=False raises.
        """
        if not secure:
            self.rejected_insecure += 1
            raise ValueError(
                f'refusing to store key material from an INSECURE session '
                f'(session_id={session_id}). Bits from aborted or unverified '
                f'sessions must never enter the pool: retrieve_key() splices '
                f'across records, so one bad record would contaminate an '
                f'operational key.')
        if len(key_bits) == 0:
            return None
        with self._lock:
            now = time.time()
            ttl = self.max_age_sec if ttl_sec is None else ttl_sec
            kid = key_id or str(_uuid.uuid4())
            rec = {
                'key_id': kid,
                'endpoint_a': self.endpoint_a,
                'endpoint_b': self.endpoint_b,
                'connection_id': connection_id,
                'session_id': session_id if session_id is not None else self._counter,
                'created_at': now,
                'expires_at': (now + ttl) if ttl is not None else None,
                'total_bits': int(len(key_bits)),
                'remaining': np.array(key_bits, dtype=np.uint8),
                'status': KeyStatus.AVAILABLE,
                'secure': True,
                'reserved_by': None,
                'consumed_at': None,
                'expired_at': None,
                'revoked_at': None,
                'destroyed_at': None,
                'timestamp': now,          # back-compat
            }
            self._counter += 1
            self.pool.append(rec)
            self._by_id[kid] = rec
            self.total_bits_generated += len(key_bits)
            self.sessions_admitted += 1
            if verbose:
                print(f"Key {kid[:8]} stored ({len(key_bits)} bits). "
                      f"Pool: {len(self.pool)} records, "
                      f"{self.total_bits_generated} total bits generated")
            return kid

    # ---------------- atomic reservation (ITEM 27) --------------------
    def reserve(self, n_bits, request_id=None, allow_splice=True):
        """Atomically claim n_bits. Returns a reservation dict or None.

        A repeated `request_id` returns the EXISTING reservation rather than
        allocating a second one - duplicate-request protection, so a client that
        retries a timed-out call does not silently consume twice.
        """
        with self._lock:
            self.requests_total += 1
            if request_id is not None and request_id in self._reservations:
                return self._reservations[request_id]      # idempotent

            t0 = time.time()
            self._expire_due(t0)
            n = int(n_bits)
            if n <= 0:
                self.requests_failed += 1
                return None

            live = [e for e in self.pool if self._is_live(e, t0)
                    and e['status'] == KeyStatus.AVAILABLE
                    and len(e['remaining']) > 0]

            # Prefer a single record that can fund the whole request.
            chosen = []
            single = next((e for e in live if len(e['remaining']) >= n), None)
            if single is not None:
                chosen = [(single, n)]
            elif allow_splice and sum(len(e['remaining']) for e in live) >= n:
                need = n
                for e in live:
                    if need <= 0:
                        break
                    take = min(need, len(e['remaining']))
                    chosen.append((e, take))
                    need -= take
            else:
                self.requests_failed += 1
                self.underflow_events += 1
                return None

            rid = request_id or str(_uuid.uuid4())
            chunks = []
            for rec, take in chosen:
                chunks.append(rec['remaining'][:take].copy())
                rec['remaining'] = rec['remaining'][take:]
                rec['status'] = KeyStatus.RESERVED
                rec['reserved_by'] = rid
            reservation = {
                'request_id': rid,
                'key_id': str(_uuid.uuid4()),          # the DELIVERED key's id
                'source_key_ids': [r['key_id'] for r, _ in chosen],
                'bits': np.concatenate(chunks),
                'n_bits': n,
                'reserved_at': t0,
                'committed': False,
                'segments': len(chosen),
            }
            self._reservations[rid] = reservation
            return reservation

    def commit_reservation(self, rid):
        """Finalise a reservation: the bits are delivered and gone."""
        with self._lock:
            r = self._reservations.get(rid)
            if r is None or r['committed']:
                return None
            r['committed'] = True
            now = time.time()
            self.total_bits_consumed += r['n_bits']
            if r['segments'] > 1:
                self.spliced_retrievals += 1
                self.splice_segments += r['segments']
            for kid in r['source_key_ids']:
                rec = self._by_id[kid]
                if len(rec['remaining']) == 0:
                    rec['status'] = KeyStatus.CONSUMED
                    rec['consumed_at'] = now
                else:
                    rec['status'] = KeyStatus.AVAILABLE
                rec['reserved_by'] = None
            self.requests_succeeded += 1
            self.delivery_latencies.append(now - r['reserved_at'])
            return r['bits']

    def release_reservation(self, rid):
        """Roll a reservation back - the bits return to the pool unspent."""
        with self._lock:
            r = self._reservations.pop(rid, None)
            if r is None or r['committed']:
                return False
            offset = 0
            for kid in r['source_key_ids']:
                rec = self._by_id[kid]
                take = min(r['n_bits'] - offset, r['n_bits'])
                rec['remaining'] = np.concatenate(
                    [r['bits'][offset:offset + take], rec['remaining']])
                offset += take
                rec['status'] = KeyStatus.AVAILABLE
                rec['reserved_by'] = None
            return True

    # ---------------- simple path (unchanged API) ---------------------
    def retrieve_key(self, min_length=None, allow_splice=True, request_id=None):
        """Return exactly min_length bits, consuming only those bits.

        Now reserve + commit under one lock, so two concurrent callers can never
        be handed the same bits. Splicing across records remains the intended
        path (sessions are deliberately moderate; see BB84_SESSION_SIZES).

        INTERNAL KMS call. Application code goes through
        QKDKeyDeliveryAPI.request_key() (Step 1C).
        """
        if min_length is None:
            min_length = OPERATIONAL_KEY_BITS
        r = self.reserve(min_length, request_id=request_id, allow_splice=allow_splice)
        if r is None:
            return None
        if r['committed']:                 # idempotent replay of a finished call
            return r['bits']
        return self.commit_reservation(r['request_id'])

    def available_bits(self):
        now = time.time()
        with self._lock:
            self._expire_due(now)
            return int(sum(len(e['remaining']) for e in self.pool
                           if self._is_live(e, now)))

    # ---------------- revoke / destroy (ITEM 29) ----------------------
    def revoke(self, key_id, reason='policy'):
        with self._lock:
            rec = self._by_id.get(key_id)
            if rec is None or rec['status'] == KeyStatus.DESTROYED:
                return False
            rec['status'] = KeyStatus.REVOKED
            rec['revoked_at'] = time.time()
            rec['revoke_reason'] = reason
            return True

    def destroy(self, key_id, reason='retired'):
        """ITEM 29: secure deletion. The buffer is overwritten in place before
        the reference is dropped, so retired material is not merely
        unreferenced - it is unreadable."""
        with self._lock:
            rec = self._by_id.get(key_id)
            if rec is None or rec['status'] == KeyStatus.DESTROYED:
                return False
            n = int(len(rec['remaining']))
            if isinstance(rec['remaining'], np.ndarray):
                rec['remaining'][:] = 0            # overwrite
            rec['remaining'] = np.array([], dtype=np.uint8)
            rec['status'] = KeyStatus.DESTROYED
            rec['destroyed_at'] = time.time()
            rec['destroy_reason'] = reason
            self.destroyed_bits += n
            return True

    def destroy_terminal(self):
        """Zeroise every record that has reached a terminal state and still
        holds bits (consumed remainders, expired and revoked material)."""
        n = 0
        with self._lock:
            self._expire_due()
            for rec in self.pool:
                if rec['status'] in (KeyStatus.CONSUMED, KeyStatus.EXPIRED,
                                     KeyStatus.REVOKED) and len(rec['remaining']):
                    self.destroy(rec['key_id'], reason=rec['status'].lower())
                    n += 1
        return n

    def purge_expired(self, zeroize=True):
        with self._lock:
            self._expire_due()
            dropped = 0
            keep = []
            for rec in self.pool:
                if rec['status'] in (KeyStatus.EXPIRED, KeyStatus.DESTROYED):
                    if zeroize:
                        self.destroy(rec['key_id'], reason='purged')
                    dropped += 1
                else:
                    keep.append(rec)
            self.pool = keep
            self._by_id = {r['key_id']: r for r in keep}
            return dropped

    # ---------------- introspection -----------------------------------
    def records_dataframe(self):
        """ITEM 24: the key register, as a table."""
        with self._lock:
            return pd.DataFrame([{
                'key_id': r['key_id'][:8], 'endpoint_a': r['endpoint_a'],
                'endpoint_b': r['endpoint_b'], 'connection_id': r['connection_id'],
                'session_id': r['session_id'],
                'created_at': r['created_at'], 'expires_at': r['expires_at'],
                'total_bits': r['total_bits'], 'remaining_bits': len(r['remaining']),
                'status': r['status'],
            } for r in self.pool])

    def status_counts(self):
        out = {}
        with self._lock:
            self._expire_due()
            for r in self.pool:
                out[r['status']] = out.get(r['status'], 0) + 1
        return out

    def get_pool_status(self):
        now = time.time()
        with self._lock:
            self._expire_due(now)
            live = [e for e in self.pool if self._is_live(e, now)
                    and len(e['remaining']) > 0]
            total_bits = int(sum(len(e['remaining']) for e in live))
            return {
                'total_keys': len(self.pool),
                'available_keys': len(live),
                'total_available_bits': total_bits,
                'total_bits_generated': int(self.total_bits_generated),
                'total_bits_consumed': int(self.total_bits_consumed),
                'spliced_retrievals': int(self.spliced_retrievals),
                'mean_splice_segments': (self.splice_segments / self.spliced_retrievals
                                         if self.spliced_retrievals else 0.0),
                'secure_sessions_admitted': int(self.sessions_admitted),
                'insecure_admissions_rejected': int(self.rejected_insecure),
                'fundable_operational_keys': total_bits // max(1, OPERATIONAL_KEY_BITS),
            }

    def kms_metrics(self):
        """ITEM 32: the operational metrics a KMS is judged on."""
        st = self.get_pool_status()
        gen = max(1, self.total_bits_generated)
        return {
            'key_availability_%': 100.0 * (st['fundable_operational_keys'] > 0),
            'pool_occupancy_bits': st['total_available_bits'],
            'pool_occupancy_keys': st['fundable_operational_keys'],
            'pool_underflow_events': self.underflow_events,
            'expired_unused_bits': self.expired_unused_bits,
            'destroyed_bits': self.destroyed_bits,
            'key_utilization_%': 100.0 * self.total_bits_consumed / gen,
            'wasted_bits_%': 100.0 * self.expired_unused_bits / gen,
            'requests_total': self.requests_total,
            'request_success_rate_%': (100.0 * self.requests_succeeded /
                                       max(1, self.requests_total)),
            'mean_delivery_latency_ms': (1000.0 * float(np.mean(self.delivery_latencies))
                                         if self.delivery_latencies else 0.0),
            'status_counts': self.status_counts(),
        }


class SynchronizedKeyStores:
    """ITEM 26: two logical KMS stores - Alice's and Bob's - holding the SAME
    key_ids over the same key material.

    A single shared pool silently assumed both endpoints could read one object,
    which is not how a QKD link works: each side runs its own key management
    entity, and they agree because BB84 produced identical bits and they index
    them by a shared key_id. Modelling both sides makes that agreement testable
    rather than assumed - `verify_synchronised()` checks that the two registers
    hold the same ids, the same lengths, and the same bits.
    """

    def __init__(self, max_age_sec=None, endpoint_a='alice', endpoint_b='bob'):
        self.alice = KeyPool(max_age_sec=max_age_sec, endpoint_a=endpoint_a,
                             endpoint_b=endpoint_b, label=f'{endpoint_a}-kms')
        self.bob = KeyPool(max_age_sec=max_age_sec, endpoint_a=endpoint_a,
                           endpoint_b=endpoint_b, label=f'{endpoint_b}-kms')

    def store_key(self, key_bits, session_id=None, secure=True, **kw):
        """Both endpoints admit the same bits under the SAME key_id."""
        kid = self.alice.store_key(key_bits, session_id=session_id,
                                   secure=secure, key_id=None, **kw)
        self.bob.store_key(key_bits, session_id=session_id, secure=secure,
                           key_id=kid, **kw)
        return kid

    def retrieve_both(self, min_length=None, request_id=None):
        """Each side independently retrieves - they must get identical bits."""
        rid = request_id or str(_uuid.uuid4())
        a = self.alice.retrieve_key(min_length, request_id=rid)
        b = self.bob.retrieve_key(min_length, request_id=rid)
        return a, b

    def verify_synchronised(self):
        ids_a = [r['key_id'] for r in self.alice.pool]
        ids_b = [r['key_id'] for r in self.bob.pool]
        if ids_a != ids_b:
            return False, 'key_id registers differ'
        for ra, rb in zip(self.alice.pool, self.bob.pool):
            if not np.array_equal(ra['remaining'], rb['remaining']):
                return False, f'key material differs for {ra["key_id"][:8]}'
            if ra['status'] != rb['status']:
                return False, f'status differs for {ra["key_id"][:8]}'
        return True, f'{len(ids_a)} key records synchronised across both endpoints'


class BB84Metrics:
    """Performance metrics. Key rate uses quantum channel time, not wall clock."""

    def __init__(self, pulse_rate_hz=PULSE_RATE_HZ):
        self.sessions = []
        self.pulse_rate_hz = pulse_rate_hz

    def record_session(self, n_bits_sent, final_key_length, qber, secure):
        channel_time = n_bits_sent / self.pulse_rate_hz if self.pulse_rate_hz else 0.0
        self.sessions.append({
            'n_bits_sent': n_bits_sent,
            'final_key_length': final_key_length,
            'qber': qber,
            'secure': secure,
            'channel_time_sec': channel_time,
            'key_rate': final_key_length / channel_time if channel_time > 0 else 0.0,
        })

    def print_report(self):
        if not self.sessions:
            print('No sessions recorded.'); return
        secure_sessions = [s for s in self.sessions if s['secure']]
        print('=' * 50)
        print('       BB84 PERFORMANCE METRICS REPORT')
        print('=' * 50)
        print(f"Total sessions run:        {len(self.sessions)}")
        print(f"Secure sessions:           {len(secure_sessions)}")
        print(f"Key availability:          {len(secure_sessions)/len(self.sessions)*100:.1f}%")
        if secure_sessions:
            print(f"Avg QBER (secure):         {np.mean([s['qber'] for s in secure_sessions])*100:.2f}%")
            print(f"Avg key rate:              {np.mean([s['key_rate'] for s in secure_sessions]):.1f} bits/sec (quantum-channel time)")
            print(f"Total secret bits gen'd:   {sum(s['final_key_length'] for s in secure_sessions)} bits")
        print('=' * 50)


# ===================================================================
# notebook cell [30] -> session
#   provides: run_bb84_simulation
# ===================================================================
def run_bb84_simulation(n_bits=500, error_rate=0.02, eve_rate=0.0,
                        session_id=0, rng=None, seed=SEED, verbose=False,
                        sample_fraction=0.25, loss_rate=0.0, qber_detail=None,
                        auth_channel=None, auth_reserve=None, tamper_phase=None):
    """Run one complete BB84 session.

    Returns (final_key, qber, secure, channel_time, reason).
    `secure` is True only if QBER passes AND Alice/Bob keys verify identical.

    `qber` is the POINT estimate (the observable telemetry feature). The abort
    decision is made on the upper confidence bound inside QBERCalculator.

    Pass a dict as `qber_detail` to receive the full QBER estimate - point
    value, upper bound, sample size, errors, confidence - plus `leak_ec` and
    `final_key_len`, without changing the return signature. This is how sampling
    uncertainty reaches the telemetry exporters and the finite-key comparison.
    """
    detail = {} if qber_detail is None else qber_detail

    # --- Classical-channel authentication (2026-09-12) --------------------
    # Every public message below is authenticated. Without this BB84 has no
    # security at all: Eve can run the protocol separately with each party and
    # both accept a key she holds, with QBER looking perfect throughout.
    # `tamper_phase` names a phase to corrupt in transit, for the rejection test.
    if auth_channel is None:
        auth_reserve = auth_reserve or AuthKeyReserve(rng=make_rng(seed))
        auth_channel = AuthenticatedClassicalChannel(auth_reserve, rng=make_rng(seed))
    auth_channel.begin_session()
    detail['auth_bits_before'] = auth_channel.bits_consumed
    if rng is None:
        rng = make_rng(seed)
    if verbose:
        print(f"\n=== BB84 SESSION {session_id} | {n_bits} bits | "
              f"noise={error_rate:.3f} | eve={eve_rate:.3f} ===")

    channel_time = n_bits / PULSE_RATE_HZ  # quantum-channel time (Fix #19)

    alice = Alice(n_bits, rng=rng)
    alice.generate_random_bits(verbose)
    alice.generate_random_bases(verbose)
    circuits = alice.encode_photons(verbose)

    channel = QuantumChannel(error_rate=error_rate, eve_intercept_rate=eve_rate,
                             loss_rate=loss_rate, rng=rng, seed=seed)
    transmitted = channel.transmit(circuits, verbose)

    bob = Bob(n_bits, rng=rng, seed=seed)
    bob.generate_random_bases(verbose)
    bob.measure_photons(transmitted, verbose)

    sifter = BB84KeySifting()

    # PHASE 1 - basis announcement, authenticated.
    try:
        auth_channel.exchange('bases', alice.bases,
                              tamper=(tamper_phase == 'bases'))
    except AuthenticationError as e:
        if verbose:
            print('ABORT:', e)
        detail['auth_error'] = str(e)
        return None, 0.0, False, channel_time, 'authentication_failed'

    matching = sifter.basis_reconciliation(alice.bases, bob.bases,
                                           arrived=channel.arrived_mask,
                                           verbose=verbose)
    alice_sifted, bob_sifted = sifter.key_sifting(alice.bits, bob.measurements, matching, verbose)

    qber, secure, alice_rem, bob_rem = QBERCalculator.calculate(
        alice_sifted, bob_sifted, rng, sample_fraction=sample_fraction,
        detail=detail, verbose=verbose)

    # PHASE 2 - the QBER sample (indices and Alice's sampled bit values),
    # authenticated. An unauthenticated sample lets Eve rewrite the error
    # estimate and walk a compromised session straight through the gate.
    try:
        auth_channel.exchange('qber_sample', alice_sifted,
                              tamper=(tamper_phase == 'qber_sample'))
    except AuthenticationError as e:
        if verbose:
            print('ABORT:', e)
        detail['auth_error'] = str(e)
        return None, qber, False, channel_time, 'authentication_failed'

    if not secure:
        auth_channel.begin_session()      # drop the partial transcript
        return None, qber, False, channel_time, 'qber_above_threshold'

    ec_transcript = []
    # stats=detail lands the ITEM 21 efficiency report (errors before/after,
    # parity disclosed, efficiency f) straight into the session telemetry.
    # qber_estimate feeds Cascade's k1 ~ 0.73/QBER initial block size.
    bob_corr, alice_final, parity_leaked = ErrorCorrection.correct(
        alice_rem, bob_rem, rng, verbose=verbose, transcript=ec_transcript,
        stats=detail, qber_estimate=detail.get('qber_point'))
    detail['leak_ec'] = int(parity_leaked)

    # PHASE 3 - the full Cascade parity transcript, authenticated.
    try:
        auth_channel.exchange('error_correction', np.array(ec_transcript, dtype=np.uint8),
                              tamper=(tamper_phase == 'error_correction'))
    except AuthenticationError as e:
        if verbose:
            print('ABORT:', e)
        detail['auth_error'] = str(e)
        return None, qber, False, channel_time, 'authentication_failed'

    # Fix #5: verify reconciled keys actually agree BEFORE accepting the session.
    # ITEM 18: a short universal-hash tag under a fresh public seed, not a
    # 256-bit SHA-256 digest. The disclosed tag bits are subtracted in PA below.
    verify_seed = int(rng.integers(0, 2 ** 62))
    agree, disclosed = keys_agree(alice_final, bob_corr, seed=verify_seed)
    detail['verify_tag_bits'] = int(disclosed)
    detail['verification_failure_probability'] = 2.0 ** (-VERIFY_TAG_BITS)

    # PHASE 4 - the verification tag itself, authenticated.
    try:
        auth_channel.exchange('key_verify',
                              key_verification_tag(alice_final, verify_seed),
                              tamper=(tamper_phase == 'key_verify'))
    except AuthenticationError as e:
        if verbose:
            print('ABORT:', e)
        detail['auth_error'] = str(e)
        return None, qber, False, channel_time, 'authentication_failed'

    # Close the authenticated channel. In transcript mode this is where the
    # single session tag is compared, so ANY alteration in ANY phase surfaces
    # here. In per-phase mode each message was already checked and this is a
    # no-op.
    try:
        auth_channel.close()
    except AuthenticationError as e:
        if verbose:
            print('ABORT:', e)
        detail['auth_error'] = str(e)
        return None, qber, False, channel_time, 'authentication_failed'

    detail['auth_bits_this_session'] = auth_channel.bits_consumed - detail['auth_bits_before']

    if not agree:
        if verbose:
            print('Key verification FAILED - residual errors remain. Session discarded.')
        auth_channel.begin_session()      # drop the partial transcript
        return None, qber, False, channel_time, 'key_verification_failed'

    final_key = PrivacyAmplification.amplify(
        bob_corr, qber, parity_leaked, rng,
        qber_upper=detail.get('qber_upper'), disclosed_bits=disclosed,
        stats=detail, verbose=verbose)
    detail['final_key_len'] = 0 if final_key is None else int(len(final_key))
    if final_key is None or len(final_key) == 0:
        auth_channel.begin_session()
        return None, qber, False, channel_time, 'empty_after_privacy_amplification'

    if verbose:
        print(f"Session OK - final key length: {len(final_key)} bits")
    return final_key, qber, True, channel_time, 'ok'


# ===================================================================
# notebook cell [32] -> lifecycle
#   provides: KeyLifecycleManager
# ===================================================================
# --- Step 1B: explicit key lifecycle -------------------------------------
import uuid


class KeyLifecycleManager:
    """Explicit KMS key lifecycle over a KeyPool.

    Implements the six operations a rekey actually consists of, instead of
    collapsing them into one retrieve_key() call:
      GENERATE_KEY_MATERIAL, ACTIVATE_NEW_KEY, REVOKE_OLD_KEY,
      EXPIRE_KEY, DESTROY_KEY, RETRY_WHEN_POOL_EMPTY.

    States: PENDING -> ACTIVE -> (REVOKED | EXPIRED) -> DESTROYED
    """

    PENDING = 'PENDING'; ACTIVE = 'ACTIVE'; REVOKED = 'REVOKED'
    EXPIRED = 'EXPIRED'; DESTROYED = 'DESTROYED'

    OP_GENERATE = 'GENERATE_KEY_MATERIAL'
    OP_ACTIVATE = 'ACTIVATE_NEW_KEY'
    OP_REVOKE   = 'REVOKE_OLD_KEY'
    OP_EXPIRE   = 'EXPIRE_KEY'
    OP_DESTROY  = 'DESTROY_KEY'
    OP_RETRY    = 'RETRY_WHEN_POOL_EMPTY'

    # ITEM 28: an empty pool used to be discovered only when a rekey failed.
    # `min_reserve_bits` is a safety buffer: when available key falls below it
    # the manager generates PROACTIVELY, before any request fails. Failures that
    # still happen are retried, their recovery time is logged, and a link that
    # cannot recover enters the explicit BLOCK_COMMUNICATION fallback rather
    # than silently continuing with no key.
    FALLBACK_BLOCK = 'BLOCK_COMMUNICATION'

    def __init__(self, key_pool, key_length=None, key_ttl_sec=KEY_TTL_SEC,
                 replenish_fn=None, max_retries=3, generate_sessions=4,
                 generate_session_bits=None, rng=None, seed=SEED,
                 min_reserve_keys=3, fallback_policy=None):
        self.key_pool = key_pool
        self.key_length = int(OPERATIONAL_KEY_BITS if key_length is None else key_length)
        if self.key_length < KEY_MIN_BITS:
            raise ValueError(
                f'key_length={self.key_length} is below KEY_MIN_BITS={KEY_MIN_BITS}. '
                'Short operational keys are exactly the defect this class exists to fix.')
        self.key_ttl_sec = key_ttl_sec
        self.max_retries = int(max_retries)
        self.generate_sessions = int(generate_sessions)
        self.generate_session_bits = int(generate_session_bits or BB84_SESSION_SIZES[-1])
        self.rng = rng if rng is not None else make_rng(seed)
        self.seed = seed
        self._replenish_fn = replenish_fn or self._default_replenish
        self.keys = {}          # key_id -> record
        self.active_by_conn = {}  # connection_id -> key_id
        self.min_reserve_bits = int(min_reserve_keys) * self.key_length
        self.fallback_policy = fallback_policy or self.FALLBACK_BLOCK
        self.communication_blocked = False
        self.recovery_events = []          # ITEM 28: time to recover from empty
        self.proactive_generations = 0
        self.audit_log = []
        self.counters = {op: 0 for op in (self.OP_GENERATE, self.OP_ACTIVATE,
                                          self.OP_REVOKE, self.OP_EXPIRE,
                                          self.OP_DESTROY, self.OP_RETRY)}

    # ---------------- audit ----------------
    def _audit(self, op, key_id=None, connection_id=None, session_id=None, detail=''):
        self.counters[op] = self.counters.get(op, 0) + 1
        self.audit_log.append({'timestamp': time.time(), 'operation': op,
                               'key_id': key_id, 'connection_id': connection_id,
                               'session_id': session_id, 'detail': detail})

    def audit_dataframe(self):
        return pd.DataFrame(self.audit_log)

    # ---------------- GENERATE_KEY_MATERIAL ----------------
    def _default_replenish(self, target_bits, session_id=None):
        """Run fresh BB84 sessions into the pool until target_bits are added
        or the session budget is exhausted. Returns bits actually added."""
        added = 0
        for k in range(self.generate_sessions):
            if added >= target_bits:
                break
            err = float(self.rng.uniform(0.0, 0.03))
            key, qber, secure, ctime, reason = run_bb84_simulation(
                n_bits=self.generate_session_bits, error_rate=err, eve_rate=0.0,
                session_id=(session_id or 0) * 1000 + k, rng=self.rng,
                seed=self.seed, verbose=False)
            if secure and key is not None and len(key) > 0:
                # secure=secure is explicit: KeyPool.store_key refuses insecure
                # material outright, so aborted sessions can never be spliced in.
                self.key_pool.store_key(key, session_id=f'gen-{session_id}-{k}',
                                        secure=secure)
                added += len(key)
        return added

    def generate_key_material(self, target_bits=None, session_id=None):
        """GENERATE_KEY_MATERIAL - create NEW secret bits (not a retrieval)."""
        target = int(target_bits or max(self.key_length * 2, OPERATIONAL_KEY_BITS))
        added = int(self._replenish_fn(target, session_id=session_id))
        self._audit(self.OP_GENERATE, session_id=session_id,
                    detail=f'target={target} added={added}')
        return added

    # ---------------- reservation + RETRY_WHEN_POOL_EMPTY ----------------
    def _reserve_bits(self, key_length):
        return self.key_pool.retrieve_key(min_length=key_length)

    def retry_when_pool_empty(self, key_length, session_id=None):
        """RETRY_WHEN_POOL_EMPTY - bounded generate-and-retry.
        Returns (bits_or_None, n_retries, bits_generated)."""
        generated = 0
        for attempt in range(1, self.max_retries + 1):
            self._audit(self.OP_RETRY, session_id=session_id,
                        detail=f'attempt={attempt}/{self.max_retries} '
                               f'need={key_length} '
                               f'have={self.key_pool.get_pool_status()["total_available_bits"]}')
            generated += self.generate_key_material(
                target_bits=max(key_length * 2, OPERATIONAL_KEY_BITS),
                session_id=session_id)
            bits = self._reserve_bits(key_length)
            if bits is not None:
                return bits, attempt, generated
        return None, self.max_retries, generated

    # ---------------- ACTIVATE_NEW_KEY ----------------
    def activate_new_key(self, connection_id, key_bits, session_id=None,
                         usage_policy=None):
        """ACTIVATE_NEW_KEY - register reserved bits as an ACTIVE key."""
        now = time.time()
        key_id = str(uuid.uuid4())
        record = {
            'key_id': key_id,
            'connection_id': connection_id,
            'state': self.PENDING,
            'material': np.array(key_bits, dtype=np.uint8),
            'length_bits': int(len(key_bits)),
            'created_at': now,
            'activated_at': None,
            'expires_at': now + self.key_ttl_sec,
            'revoked_at': None, 'revoke_reason': None,
            'expired_at': None, 'destroyed_at': None,
            'session_id': session_id,
            'usage_policy': usage_policy or default_usage_policy(len(key_bits)),
            'delivered_to': [],
        }
        self.keys[key_id] = record
        record['state'] = self.ACTIVE
        record['activated_at'] = now
        self.active_by_conn[connection_id] = key_id
        self._audit(self.OP_ACTIVATE, key_id, connection_id, session_id,
                    detail=f'{record["length_bits"]} bits, ttl={self.key_ttl_sec}s')
        return record

    # ---------------- REVOKE / EXPIRE / DESTROY ----------------
    def revoke_old_key(self, key_id, reason='superseded_by_rekey'):
        """REVOKE_OLD_KEY - a revoked key must not encrypt new traffic."""
        rec = self.keys.get(key_id)
        if rec is None or rec['state'] in (self.DESTROYED,):
            return False
        rec['state'] = self.REVOKED
        rec['revoked_at'] = time.time()
        rec['revoke_reason'] = reason
        if self.active_by_conn.get(rec['connection_id']) == key_id:
            self.active_by_conn.pop(rec['connection_id'], None)
        self._audit(self.OP_REVOKE, key_id, rec['connection_id'],
                    rec['session_id'], detail=reason)
        return True

    def expire_key(self, key_id, reason='ttl_elapsed'):
        """EXPIRE_KEY - time-based retirement."""
        rec = self.keys.get(key_id)
        if rec is None or rec['state'] == self.DESTROYED:
            return False
        rec['state'] = self.EXPIRED
        rec['expired_at'] = time.time()
        if self.active_by_conn.get(rec['connection_id']) == key_id:
            self.active_by_conn.pop(rec['connection_id'], None)
        self._audit(self.OP_EXPIRE, key_id, rec['connection_id'],
                    rec['session_id'], detail=reason)
        return True

    def destroy_key(self, key_id, reason='retired'):
        """DESTROY_KEY - zeroise the buffer in place, then drop the reference."""
        rec = self.keys.get(key_id)
        if rec is None or rec['state'] == self.DESTROYED:
            return False
        mat = rec.get('material')
        if isinstance(mat, np.ndarray):
            mat[:] = 0                      # overwrite before release
        rec['material'] = None
        rec['state'] = self.DESTROYED
        rec['destroyed_at'] = time.time()
        self.active_by_conn.pop(rec['connection_id'], None) \
            if self.active_by_conn.get(rec['connection_id']) == key_id else None
        self._audit(self.OP_DESTROY, key_id, rec['connection_id'],
                    rec['session_id'], detail=reason)
        return True

    def sweep_expired(self, destroy=True):
        """Retire every ACTIVE key whose TTL has elapsed."""
        now = time.time()
        n = 0
        for key_id, rec in list(self.keys.items()):
            if rec['state'] == self.ACTIVE and now > rec['expires_at']:
                self.expire_key(key_id, reason='ttl_elapsed')
                if destroy:
                    self.destroy_key(key_id, reason='expired')
                n += 1
        return n

    # ---------------- full rekey orchestration ----------------
    def ensure_safety_buffer(self, session_id=None):
        """ITEM 28: generate BEFORE the pool runs dry, not after a failure."""
        available = self.key_pool.get_pool_status()['total_available_bits']
        if available >= self.min_reserve_bits:
            return 0
        added = self.generate_key_material(
            target_bits=self.min_reserve_bits - available, session_id=session_id)
        if added:
            self.proactive_generations += 1
        return added

    def rekey(self, connection_id, session_id=None, key_length=None,
              usage_policy=None):
        """One rekey = reserve (retry/generate if needed) -> ACTIVATE_NEW_KEY
        -> REVOKE_OLD_KEY -> EXPIRE_KEY -> DESTROY_KEY.
        Returns a result dict; ops[] names every lifecycle op performed."""
        kl = int(key_length or self.key_length)
        ops, retries, generated = [], 0, 0
        self.sweep_expired()
        t_request = time.time()

        # ITEM 28: top up proactively while there is still key to work with.
        pre = self.ensure_safety_buffer(session_id)
        if pre:
            ops.append(self.OP_GENERATE)
            generated += pre

        bits = self._reserve_bits(kl)
        if bits is None:
            bits, retries, generated = self.retry_when_pool_empty(kl, session_id)
            ops.append(self.OP_RETRY)
            if generated:
                ops.append(self.OP_GENERATE)
        if bits is None:
            # ITEM 28: an unrecoverable request is a communication outage, and
            # the safe fallback is to BLOCK rather than to proceed unprotected.
            self.communication_blocked = True
            self.recovery_events.append({'session_id': session_id,
                                         'recovered': False,
                                         'recovery_sec': None,
                                         'retries': retries})
            self._audit(self.OP_RETRY, session_id=session_id,
                        detail=f'unrecoverable; fallback={self.fallback_policy}')
            return {'ok': False, 'reason': 'POOL_EXHAUSTED', 'key_id': None,
                    'key': None, 'ops': ops, 'retries': retries,
                    'generated_bits': generated, 'connection_id': connection_id,
                    'fallback': self.fallback_policy}
        if retries:
            # Recovered after at least one failed reservation - record how long.
            self.recovery_events.append({'session_id': session_id,
                                         'recovered': True,
                                         'recovery_sec': time.time() - t_request,
                                         'retries': retries})
        self.communication_blocked = False

        previous_id = self.active_by_conn.get(connection_id)
        record = self.activate_new_key(connection_id, bits, session_id, usage_policy)
        ops.append(self.OP_ACTIVATE)

        if previous_id is not None and previous_id != record['key_id']:
            if self.revoke_old_key(previous_id, 'superseded_by_rekey'):
                ops.append(self.OP_REVOKE)
            if self.expire_key(previous_id, 'superseded_by_rekey'):
                ops.append(self.OP_EXPIRE)
            if self.destroy_key(previous_id, 'superseded_by_rekey'):
                ops.append(self.OP_DESTROY)

        return {'ok': True, 'reason': 'OK', 'key_id': record['key_id'],
                'key': record['material'], 'key_length': record['length_bits'],
                'activated_at': record['activated_at'],
                'expires_at': record['expires_at'],
                'usage_policy': record['usage_policy'],
                'previous_key_id': previous_id, 'ops': ops, 'retries': retries,
                'generated_bits': generated, 'connection_id': connection_id}

    # ---------------- introspection ----------------
    def state_counts(self):
        out = {}
        for rec in self.keys.values():
            out[rec['state']] = out.get(rec['state'], 0) + 1
        return out

    def summary(self):
        rec = [r for r in self.recovery_events if r['recovered']]
        return {'keys_tracked': len(self.keys), 'states': self.state_counts(),
                'operations': dict(self.counters),
                'proactive_generations': self.proactive_generations,
                'min_reserve_bits': self.min_reserve_bits,
                'recovery_events': len(self.recovery_events),
                'mean_recovery_sec': (float(np.mean([r['recovery_sec'] for r in rec]))
                                      if rec else None),
                'communication_blocked': self.communication_blocked,
                'fallback_policy': self.fallback_policy,
                'pool': self.key_pool.get_pool_status()}


# ===================================================================
# notebook cell [34] -> delivery
#   provides: KeyDeliveryError, QKDKeyDeliveryAPI
# ===================================================================
# --- Step 1C: application-facing key delivery (ETSI GS QKD 014 style) -----
import base64


class KeyDeliveryError(RuntimeError):
    """Raised for application-visible key-delivery failures."""


class QKDKeyDeliveryAPI:
    """The ONLY interface application code should use to obtain key material.

    Deliberately hides the KeyPool: no method returns a pool entry, a bit
    offset, or the KeyPool object itself.
    """

    def __init__(self, lifecycle, default_key_length=None):
        self.__kms = lifecycle                     # name-mangled: not part of the API
        self.default_key_length = int(default_key_length or lifecycle.key_length)
        self._connections = {}                     # connection_id -> {'peers': (a, b)}
        self._index = {}                           # (connection_id, key_id) -> key_id

    # ---------------- connection management ----------------
    def open_connection(self, connection_id, initiator='alice', responder='bob'):
        self._connections[connection_id] = {'peers': (initiator, responder),
                                            'opened_at': time.time()}
        return {'connection_id': connection_id, 'peers': (initiator, responder),
                'key_size_bits': self.default_key_length}

    def _require_conn(self, connection_id):
        if connection_id not in self._connections:
            # auto-open keeps the demo terse; a real KMS would 404 here
            self.open_connection(connection_id)
        return self._connections[connection_id]

    # ---------------- ETSI 014: GET /enc_keys ----------------
    def request_key(self, connection_id, key_length=None, session_id=None):
        """Initiator side. Returns key_id, key material, expiry, usage policy."""
        self._require_conn(connection_id)
        kl = int(key_length or self.default_key_length)
        if kl < KEY_MIN_BITS:
            raise KeyDeliveryError(
                f'requested key_length={kl} bits is below the minimum '
                f'operational size KEY_MIN_BITS={KEY_MIN_BITS}.')
        result = self.__kms.rekey(connection_id=connection_id,
                                  session_id=session_id, key_length=kl)
        if not result['ok']:
            raise KeyDeliveryError(
                f'key delivery failed for {connection_id}: {result["reason"]} '
                f'(after {result["retries"]} retry attempt(s), '
                f'{result["generated_bits"]} bits generated)')
        key_id = result['key_id']
        self._index[(connection_id, key_id)] = key_id
        rec = self.__kms.keys[key_id]
        rec['delivered_to'].append(self._connections[connection_id]['peers'][0])
        return self._render(rec)

    # ---------------- ETSI 014: GET /dec_keys?key_ID=... ----------------
    def get_key_with_key_id(self, connection_id, key_id, peer=None):
        """Responder side. Retrieves the SAME key the initiator was given."""
        self._require_conn(connection_id)
        if (connection_id, key_id) not in self._index:
            raise KeyDeliveryError(
                f'key_id {key_id} is not available on connection {connection_id}.')
        rec = self.__kms.keys.get(key_id)
        if rec is None or rec['state'] != KeyLifecycleManager.ACTIVE:
            raise KeyDeliveryError(
                f'key_id {key_id} is not ACTIVE '
                f'(state={None if rec is None else rec["state"]}).')
        if time.time() > rec['expires_at']:
            self.__kms.expire_key(key_id); self.__kms.destroy_key(key_id, 'expired')
            raise KeyDeliveryError(f'key_id {key_id} has expired.')
        peer = peer or self._connections[connection_id]['peers'][1]
        if rec['usage_policy'].get('single_use_per_peer') and peer in rec['delivered_to']:
            raise KeyDeliveryError(
                f'key_id {key_id} was already delivered to peer {peer!r}; '
                'single_use_per_peer policy forbids re-delivery.')
        rec['delivered_to'].append(peer)
        return self._render(rec)

    # ---------------- release / status ----------------
    def release_key(self, connection_id, key_id, reason='released_by_application'):
        if (connection_id, key_id) not in self._index:
            return False
        self.__kms.revoke_old_key(key_id, reason)
        self.__kms.expire_key(key_id, reason)
        return self.__kms.destroy_key(key_id, reason)

    def status(self, connection_id=None):
        pool = self.__kms.key_pool.get_pool_status()
        kl = self.default_key_length
        return {'connection_id': connection_id,
                'source_KME_ID': 'alice-kme', 'target_KME_ID': 'bob-kme',
                'key_size_bits': kl,
                'stored_key_count': int(pool['total_available_bits'] // kl),
                'available_bits': int(pool['total_available_bits']),
                'max_key_per_request': max(1, int(pool['total_available_bits'] // kl)),
                'key_ttl_sec': self.__kms.key_ttl_sec}

    # ---------------- rendering (no internals leak) ----------------
    @staticmethod
    def _render(rec):
        bits = np.asarray(rec['material'], dtype=np.uint8)
        pad = (-len(bits)) % 8
        padded = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)]) if pad else bits
        raw = np.packbits(padded).tobytes()
        return {
            'key_id': rec['key_id'],
            'key': base64.b64encode(raw).decode('ascii'),   # ETSI 014 Key container
            'key_bits': bits.copy(),                        # convenience for this notebook
            'key_length_bits': rec['length_bits'],
            'expires_at': rec['expires_at'],
            'expires_in_sec': max(0.0, rec['expires_at'] - time.time()),
            'usage_policy': dict(rec['usage_policy']),
            'state': rec['state'],
        }


# ===================================================================
# notebook cell [36] -> secure_channel
#   provides: KeyReuseViolation, QKDSecureChannel (AES-GCM base class)
# ===================================================================
# --- End-to-end secure communication over QKD-delivered keys -------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _AEAD_AVAILABLE = True
except ImportError:                      # pragma: no cover
    _AEAD_AVAILABLE = False
    class InvalidTag(Exception):
        pass
    print('*** `cryptography` is not installed - run: pip install cryptography\n'
          '    The end-to-end demonstration below CANNOT run without it, and the '
          'framework\'s\n    central E2E claim is unevidenced until it does. '
          'Install it and re-run this cell. ***')


class KeyReuseViolation(RuntimeError):
    """Raised when a (key, nonce) pair would be reused - ITEM 30."""


class QKDSecureChannel:
    """AES-256-GCM sender/receiver keyed entirely by the QKD key-delivery API.

    Keys arrive through QKDKeyDeliveryAPI.request_key() and are fetched by the
    receiver with get_key_with_key_id(); the channel never touches the key pool.
    """

    def __init__(self, api, connection_id='alice<->bob', single_use=True,
                 max_messages_per_key=1, algorithm='AES-256-GCM'):
        self.api = api
        self.connection_id = connection_id
        self.single_use = bool(single_use)
        self.max_messages_per_key = 1 if single_use else int(max_messages_per_key)
        self.algorithm = algorithm
        self._sender_key = None          # {key_id, bytes, uses, nonces}
        self._receiver_cache = {}        # key_id -> key bytes
        self.metrics = {
            'messages_sent': 0, 'messages_delivered': 0,
            'decryption_failures': 0, 'tampering_detected': 0,
            'policy_violations': 0, 'rekeys': 0, 'bytes_protected': 0,
            'key_requests_failed': 0,
        }
        self.log = []

    # ---------------- key handling ----------------
    @staticmethod
    def _bits_to_bytes(bits):
        b = np.asarray(bits, dtype=np.uint8)
        pad = (-len(b)) % 8
        if pad:
            b = np.concatenate([b, np.zeros(pad, dtype=np.uint8)])
        return np.packbits(b).tobytes()

    def _need_new_key(self):
        return (self._sender_key is None
                or self._sender_key['uses'] >= self.max_messages_per_key)

    def _acquire_key(self, session_id=None):
        delivered = self.api.request_key(self.connection_id,
                                         key_length=OPERATIONAL_KEY_BITS,
                                         session_id=session_id)
        self._sender_key = {'key_id': delivered['key_id'],
                            'bytes': self._bits_to_bytes(delivered['key_bits']),
                            'uses': 0, 'nonces': set(),
                            'expires_at': delivered['expires_at']}
        self.metrics['rekeys'] += 1
        return self._sender_key

    # ---------------- send ----------------
    def send(self, plaintext, associated_data=b'qkd-e2e', session_id=None):
        """Encrypt one message. Returns the wire envelope."""
        if not _AEAD_AVAILABLE:
            raise RuntimeError('cryptography is required for the E2E demonstration.')
        if self._need_new_key():
            try:
                self._acquire_key(session_id=session_id)
            except KeyDeliveryError as e:
                self.metrics['key_requests_failed'] += 1
                raise
        k = self._sender_key

        # ITEM 30: a fresh nonce for every message under this key, and a hard
        # refusal if one would repeat. GCM nonce reuse under the same key leaks
        # the XOR of the plaintexts AND the authentication subkey - it is not a
        # hygiene issue, it is a total break.
        nonce = k['uses'].to_bytes(12, 'big')
        if nonce in k['nonces']:
            self.metrics['policy_violations'] += 1
            raise KeyReuseViolation(
                f'nonce {nonce.hex()} already used under key {k["key_id"][:8]}. '
                'Refusing to encrypt: AES-GCM nonce reuse under one key is a '
                'complete loss of confidentiality and integrity.')
        k['nonces'].add(nonce)

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        ct = AESGCM(k['bytes']).encrypt(nonce, plaintext, associated_data)
        k['uses'] += 1
        self.metrics['messages_sent'] += 1
        self.metrics['bytes_protected'] += len(plaintext)
        env = {'key_id': k['key_id'], 'nonce': nonce, 'ciphertext': ct,
               'associated_data': associated_data}
        self.log.append({'event': 'sent', 'key_id': k['key_id'][:8],
                         'bytes': len(plaintext), 'uses_of_key': k['uses']})
        return env

    # ---------------- receive ----------------
    def receive(self, envelope, tamper=False):
        """Fetch the key by key_id and decrypt. Returns plaintext or None."""
        if not _AEAD_AVAILABLE:
            raise RuntimeError('cryptography is required for the E2E demonstration.')
        kid = envelope['key_id']
        if kid not in self._receiver_cache:
            try:
                delivered = self.api.get_key_with_key_id(self.connection_id, kid)
            except KeyDeliveryError as e:
                self.metrics['decryption_failures'] += 1
                self.log.append({'event': 'key_fetch_failed', 'key_id': kid[:8],
                                 'detail': str(e)})
                return None
            self._receiver_cache[kid] = self._bits_to_bytes(delivered['key_bits'])

        ct = bytearray(envelope['ciphertext'])
        if tamper and len(ct):
            ct[0] ^= 0x01                       # flip a bit in transit
        try:
            pt = AESGCM(self._receiver_cache[kid]).decrypt(
                envelope['nonce'], bytes(ct), envelope['associated_data'])
            self.metrics['messages_delivered'] += 1
            self.log.append({'event': 'delivered', 'key_id': kid[:8],
                             'bytes': len(pt)})
            return pt
        except InvalidTag:
            self.metrics['decryption_failures'] += 1
            if tamper:
                self.metrics['tampering_detected'] += 1
            self.log.append({'event': 'tamper_detected' if tamper else 'auth_failed',
                             'key_id': kid[:8]})
            return None

    def report(self):
        m = dict(self.metrics)
        m['delivery_rate_%'] = (100.0 * m['messages_delivered'] /
                                max(1, m['messages_sent']))
        m['policy'] = ('single-use key per message' if self.single_use
                       else f'up to {self.max_messages_per_key} messages/key, '
                            f'fresh nonce each')
        return m


# ===================================================================
# notebook cell [52] -> exporters
#   provides: QBERStreamExporter, PoolLevelExporter
# ===================================================================
class QBERStreamExporter:
    """Persists per-session QBER telemetry (input feed #1)."""
    def __init__(self):
        self.records = []

    def log(self, session_id, qber, secure, eve_intercept_rate,
            channel_time_sec, n_bits_sent, timestamp=None, qber_detail=None):
        # Fix (2026-09-12): sampling uncertainty is now part of the telemetry.
        # `qber` stays the point estimate (what an operator observes, and what
        # the detector is trained on); qber_upper / qber_sample_size /
        # qber_errors record HOW WELL that estimate was determined, so a later
        # analysis can tell a genuinely low QBER from a poorly-sampled one.
        # These columns are exported but deliberately NOT added to FEATURE_COLS:
        # changing the feature schema would invalidate every Part 2 result.
        rec = {
            'session_id': session_id,
            'timestamp': timestamp if timestamp is not None else time.time(),
            'qber': qber,
            'secure': secure,
            'eve_intercept_rate': eve_intercept_rate,  # simulation input -> ground-truth label source
            'channel_time_sec': channel_time_sec,
            'n_bits_sent': n_bits_sent,
        }
        d = qber_detail or {}
        rec.update({
            'qber_upper': d.get('qber_upper'),
            'qber_sample_size': d.get('qber_sample_size'),
            'qber_errors': d.get('qber_errors'),
            'qber_sifted_len': d.get('qber_sifted_len'),
            'qber_sample_fraction': d.get('qber_sample_fraction'),
            'qber_ci_width': d.get('qber_ci_width'),
            'qber_decision_basis': d.get('qber_decision_basis'),
            'ec_leak_bits': d.get('leak_ec'),
            # ITEM 21: error-correction efficiency, per session.
            'ec_errors_before': d.get('ec_errors_before'),
            'ec_errors_after': d.get('ec_errors_after'),
            'ec_parity_disclosed': d.get('ec_parity_disclosed'),
            'ec_efficiency_f': d.get('ec_efficiency_f'),
            'ec_initial_block': d.get('ec_initial_block'),
            # ITEM 19: the disclosure ledger's per-session inputs.
            'verify_tag_bits': d.get('verify_tag_bits'),
            'auth_bits_this_session': d.get('auth_bits_this_session'),
            'final_key_len': d.get('final_key_len'),
        })
        self.records.append(rec)

    def to_dataframe(self):
        return pd.DataFrame(self.records).sort_values('session_id').reset_index(drop=True)


class PoolLevelExporter:
    """Persists per-session key-pool status (input feed #2)."""
    def __init__(self):
        self.records = []

    def log(self, session_id, key_pool, timestamp=None):
        status = key_pool.get_pool_status()
        self.records.append({
            'session_id': session_id,
            'timestamp': timestamp if timestamp is not None else time.time(),
            'total_keys': status['total_keys'],
            'available_keys': status['available_keys'],
            'total_available_bits': status['total_available_bits'],
        })

    def to_dataframe(self):
        df = pd.DataFrame(self.records).sort_values('session_id').reset_index(drop=True)
        # Step 5's PoolDemandForecaster needs this directly on the pool stream
        # (not only inside extract_features()'s merged feature_df) - computed
        # once here, at the source, using the same formula.
        df['pool_depletion_rate'] = (-df['total_available_bits'].diff()).fillna(0.0)
        return df


# ===================================================================
# notebook cell [54] -> monitored
#   provides: run_monitored_session
# ===================================================================
def run_monitored_session(session_id, n_bits, error_rate, eve_rate, key_pool,
                          metrics, qber_exporter, pool_exporter, rng,
                          auth_channel=None, auth_reserve=None, verbose=False):
    """Run one BB84 session and persist its telemetry into both exporters.

    Fix (2026-09-12, AUTHENTICATION ACCOUNTING): `auth_channel` / `auth_reserve`
    are threaded through so a whole run shares ONE authentication reserve, as a
    real link does. Each session spends reserve bits on its public messages and
    then pays the reserve back from its own output BEFORE the remainder reaches
    the operational key pool. Authentication is paid first on purpose: a link
    that spends its last bits on payload keys can never talk again.
    """
    qber_detail = {}
    final_key, qber, secure, ctime, reason = run_bb84_simulation(
        n_bits=n_bits, error_rate=error_rate, eve_rate=eve_rate,
        session_id=session_id, rng=rng, verbose=verbose,
        qber_detail=qber_detail, auth_channel=auth_channel,
        auth_reserve=auth_reserve)

    # Fix (2026-09-12): pass `secure` through explicitly. KeyPool.store_key
    # raises on secure=False, so an aborted/unverified session's bits can never
    # enter the pool and therefore can never be spliced into an operational key.
    if secure and final_key is not None and len(final_key) > 0:
        # Replenish the authentication reserve first, then bank the remainder.
        if auth_reserve is not None:
            _taken, final_key = auth_reserve.replenish(final_key)
            qber_detail['auth_reserve_topup'] = int(_taken)
        if len(final_key) > 0:
            key_pool.store_key(final_key, session_id=session_id, secure=secure)

    metrics.record_session(n_bits, len(final_key) if final_key is not None else 0, qber, secure)
    qber_exporter.log(session_id, qber, secure, eve_rate, ctime, n_bits,
                      qber_detail=qber_detail)
    pool_exporter.log(session_id, key_pool)
    return final_key, qber, secure, ctime, reason


# ===================================================================
# notebook cell [56] -> features
#   provides: FEATURE_COLS, LABEL_COL, extract_features
# ===================================================================
FEATURE_COLS = [
    'qber_raw', 'rolling_mean_qber', 'rolling_var_qber', 'qber_delta',
    'pool_depletion_rate', 'pool_available_bits', 'channel_time_sec',
]
LABEL_COL = 'label_attack'


def extract_features(qber_df, pool_df, window=5, verbose=False):
    """Fuse the QBER and pool streams and compute causal rolling features.
    Returns (df, FEATURE_COLS). Rolling windows use only past/current rows.

    NOTE ON RUNTIME: this function is milliseconds even on 131k sessions
    (measured: 11 ms @ 300 rows, 14 ms @ 131,071 rows). If the CELL appears to
    hang, it is queued behind an earlier cell - the pip installs, the
    TensorFlow import, or the BB84 demo cells, which run one AerSimulator
    circuit PER PHOTON (~1,500 circuits before this point). Nothing here is a
    bottleneck.

    Guard added 2026-08-21: the merge below assumes ONE row per session_id in
    each stream. That holds for run_monitored_session(), which logs exactly one
    QBER record and one pool record per session. But if duplicates ever appear
    (re-running a generator against exporters that already hold records, or
    overlapping session_id_start ranges), a pandas many-to-many merge multiplies
    rows quadratically - 8 rows/session turns 3,000 sessions into 192,000 rows.
    That fails SILENTLY: feature_df is wrong, every downstream metric is wrong,
    and the only symptom is that things got slow. It is now checked.
    """
    # --- input validation: fail loudly rather than producing a wrong table ---
    need_q = {'session_id', 'qber', 'eve_intercept_rate', 'channel_time_sec'}
    need_p = {'session_id', 'total_available_bits'}
    missing_q = need_q - set(qber_df.columns)
    missing_p = need_p - set(pool_df.columns)
    if missing_q or missing_p:
        raise KeyError(
            f'extract_features: missing columns - qber_df {sorted(missing_q)}, '
            f'pool_df {sorted(missing_p)}. Check that both exporters were fed by '
            f'run_monitored_session() and that to_dataframe() was called.')

    dup_q = int(qber_df['session_id'].duplicated().sum())
    dup_p = int(pool_df['session_id'].duplicated().sum())
    if dup_q or dup_p:
        print(f'[extract_features] WARNING: duplicate session_id detected '
              f'(qber_df={dup_q}, pool_df={dup_p}). A many-to-many merge would '
              f'inflate the feature table and corrupt every downstream metric. '
              f'Keeping the LAST record per session. Root cause is almost always '
              f'reusing exporter objects across two generate_*_sessions() calls - '
              f'create fresh exporters per run.')
        qber_df = qber_df.drop_duplicates(subset='session_id', keep='last')
        pool_df = pool_df.drop_duplicates(subset='session_id', keep='last')

    n_in = len(qber_df)
    # validate='one_to_one' makes pandas raise instead of silently multiplying
    df = qber_df.merge(pool_df, on='session_id', suffixes=('', '_pool'),
                       validate='one_to_one')
    df = df.sort_values('session_id').reset_index(drop=True)
    if len(df) != n_in and verbose:
        print(f'[extract_features] note: {n_in} QBER rows -> {len(df)} merged rows '
              f'({n_in - len(df)} session(s) had no matching pool record).')

    q = df['qber']
    roll = q.rolling(window, min_periods=1)      # computed once, reused below
    df['qber_raw'] = q
    df['rolling_mean_qber'] = roll.mean()
    df['rolling_var_qber'] = roll.var().fillna(0.0)
    df['qber_delta'] = q.diff().fillna(0.0)
    df['pool_depletion_rate'] = (-df['total_available_bits'].diff()).fillna(0.0)
    df['pool_available_bits'] = df['total_available_bits']
    # channel_time_sec already present from the QBER stream

    # Label from the simulation INPUT (eve rate); features from OBSERVED telemetry.
    df[LABEL_COL] = (df['eve_intercept_rate'] > 0.05).astype(int)
    return df, FEATURE_COLS


# ===================================================================
# notebook cell [60] -> detector
#   provides: BaseAnomalyDetector, QKDAnomalyDetector, temporal_split (definitions only - no training)
# ===================================================================
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score)


class BaseAnomalyDetector:
    """Shared logic for tabular anomaly detectors (Fix #18).

    Subclasses set FEATURE_COLS and LABEL_COL. Provides feature scaling, a
    RF+GB+MLP ensemble, a unified predict_proba / predict_threat_score API,
    and a metrics helper. No LSTM-at-length-1 (Fix #11).
    """
    FEATURE_COLS = []
    LABEL_COL = 'label'

    def __init__(self):
        self.scaler = StandardScaler()
        self.rf = RandomForestClassifier(n_estimators=150, class_weight='balanced',
                                         random_state=SEED)
        self.gb = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1,
                                             max_depth=3, random_state=SEED)
        self.mlp = MLPClassifier(hidden_layer_sizes=(48, 24), max_iter=500,
                                 random_state=SEED)
        self.trained = False

    def _matrix(self, df):
        return df[self.FEATURE_COLS].values.astype(float)

    def train(self, df_train, verbose=False):
        X = self.scaler.fit_transform(self._matrix(df_train))
        y = df_train[self.LABEL_COL].values
        self.rf.fit(X, y)
        self.gb.fit(X, y)
        # MLP needs both classes present; guard degenerate label sets.
        if len(set(y)) > 1:
            self.mlp.fit(X, y)
            self._mlp_ok = True
        else:
            self._mlp_ok = False
        self.trained = True
        if verbose:
            print(f"[{type(self).__name__}] trained on {len(df_train)} rows")
        return self

    def _model_prob(self, X_scaled, model):
        if model == 'rf':
            return self.rf.predict_proba(X_scaled)[:, 1]
        if model == 'gb':
            return self.gb.predict_proba(X_scaled)[:, 1]
        if model == 'mlp':
            if getattr(self, '_mlp_ok', False):
                return self.mlp.predict_proba(X_scaled)[:, 1]
            return (self.rf.predict_proba(X_scaled)[:, 1] +
                    self.gb.predict_proba(X_scaled)[:, 1]) / 2
        if model == 'ensemble':
            probs = [self.rf.predict_proba(X_scaled)[:, 1],
                     self.gb.predict_proba(X_scaled)[:, 1]]
            if getattr(self, '_mlp_ok', False):
                probs.append(self.mlp.predict_proba(X_scaled)[:, 1])
            return np.mean(probs, axis=0)
        raise ValueError("model must be one of 'rf','gb','mlp','ensemble'")

    def predict_proba(self, feature_row, model='ensemble'):
        """Score one feature row (dict). Unified name used everywhere (Fix #2)."""
        x = np.array([[feature_row[c] for c in self.FEATURE_COLS]], dtype=float)
        x_scaled = self.scaler.transform(x)
        return float(self._model_prob(x_scaled, model)[0])

    def predict_threat_score(self, feature_row):
        """Alias for the ensemble score in [0,1] (kept for API compatibility)."""
        return round(self.predict_proba(feature_row, model='ensemble'), 4)

    def evaluate(self, df_eval, split_name='test', verbose=True):
        X = self.scaler.transform(self._matrix(df_eval))
        y = df_eval[self.LABEL_COL].values
        prob = self._model_prob(X, 'ensemble')
        pred = (prob >= 0.5).astype(int)
        m = {
            'split': split_name,
            'accuracy': round(accuracy_score(y, pred), 4),
            'precision': round(precision_score(y, pred, zero_division=0), 4),
            'recall': round(recall_score(y, pred, zero_division=0), 4),
            'f1': round(f1_score(y, pred, zero_division=0), 4),
            'roc_auc': round(roc_auc_score(y, prob), 4) if len(set(y)) > 1 else float('nan'),
        }
        if verbose:
            print(f"[{type(self).__name__} - {split_name}] "
                  f"Acc={m['accuracy']} Prec={m['precision']} Rec={m['recall']} "
                  f"F1={m['f1']} AUC={m['roc_auc']}")
        return m


class QKDAnomalyDetector(BaseAnomalyDetector):
    """The single QKD anomaly detector (Fix #2/#3)."""
    FEATURE_COLS = FEATURE_COLS
    LABEL_COL = LABEL_COL


def temporal_split(df, train_frac=0.7, val_frac=0.15):
    """Chronological split by session_id (Fix #10): train earliest,
    then validation, then test - no shuffling across the rolling window."""
    df = df.sort_values('session_id').reset_index(drop=True)
    n = len(df)
    i_tr = int(n * train_frac)
    i_va = int(n * (train_frac + val_frac))
    return df.iloc[:i_tr], df.iloc[i_tr:i_va], df.iloc[i_va:]


# ===================================================================
# notebook cell [66] -> nids_adapter
#   provides: NIDSFeatureError, NIDSThreatAdapter, GatedNetworkThreatDetector, load_nids_adapter (strict gate only - Kaggle path discovery and the legacy loader are NOT extracted)
# ===================================================================
# Step 4B-STRICT: NIDS threat-score adapter (PLAN 2026-09-17)
# =====================================================================
# The network threat score may enter fusion ONLY when the exported bundle is
# independently marked deployable AND reliable, its schema fingerprint and exact
# feature order match what this framework expects, the calibrator is monotone and
# the artifact files match their recorded SHA-256. Otherwise the adapter is
# UNAVAILABLE: the network contribution is zero, fallback_mode is QKD_ONLY and the
# reason is logged. No score is ever fabricated.
import hashlib as _hashlib

EXPECTED_NIDS_SCHEMA_FINGERPRINT = 'a7a1872c273eae66'   # iot23-dpkt-flow-v1 (NIDS notebook, section 7)
EXPECTED_NIDS_FEATURES = [
    'protocol', 'duration_s', 'bi_packets', 'fwd_packets', 'bwd_packets', 'bi_bytes', 'fwd_bytes',
    'bwd_bytes', 'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'fwd_pkt_len_mean',
    'bwd_pkt_len_mean', 'iat_min_s', 'iat_max_s', 'iat_mean_s', 'iat_std_s', 'fwd_iat_mean_s',
    'bwd_iat_mean_s', 'bytes_per_s', 'packets_per_s', 'fwd_bwd_packet_ratio', 'fwd_bwd_byte_ratio',
    'bwd_packet_share', 'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count', 'urg_count',
    'dst_port_class']
NIDS_RELIABLE_MODE, NIDS_FALLBACK_MODE = 'NETWORK_AND_QKD', 'QKD_ONLY'


class NIDSFeatureError(ValueError):
    pass


def _nids_sigmoid_or_iso(spec, s):
    s = np.asarray(s, dtype=float).ravel()
    if spec is None:
        return s
    if spec['method'] == 'sigmoid':
        return 1.0 / (1.0 + np.exp(-(spec['coef'] * s + spec['intercept'])))
    return np.clip(np.interp(s, spec['x'], spec['y']), 0.0, 1.0)


def _nids_spec_monotone(spec):
    if spec is None:
        return False
    if spec.get('method') == 'sigmoid':
        return float(spec.get('coef', 0)) > 0
    if spec.get('method') == 'isotonic':
        return bool(np.all(np.diff(spec['x']) >= 0) and np.all(np.diff(spec['y']) >= -1e-12))
    return False


def _nids_sha256(path):
    h = _hashlib.sha256()
    with open(path, 'rb') as fh:
        for b in iter(lambda: fh.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


class NIDSThreatAdapter:
    """Strict gate between the NIDS bundle and the fusion/decision engine."""

    def __init__(self, bundle, metadata, manifest=None, artifact_dir=None,
                 expected_fingerprint=EXPECTED_NIDS_SCHEMA_FINGERPRINT,
                 expected_features=EXPECTED_NIDS_FEATURES):
        self.bundle, self.metadata = bundle or {}, metadata or {}
        self.expected_features = list(expected_features)
        self.reasons = []
        self.fallback_log = []
        self._check(manifest, artifact_dir, expected_fingerprint)
        self.reliable = not self.reasons
        self.fallback_mode = NIDS_RELIABLE_MODE if self.reliable else NIDS_FALLBACK_MODE
        self.model_version = self.bundle.get('model_version', 'unknown')
        self.feature_schema_fingerprint = self.bundle.get('feature_schema_fingerprint')

    # ---------- load-time verification ----------
    def _check(self, manifest, artifact_dir, expected_fingerprint):
        b, m, r = self.bundle, self.metadata, self.reasons
        if not b:
            r.append('no inference bundle'); return
        if b.get('bundle_format') != 'nids-threat-bundle-v2':
            r.append(f"unsupported bundle format {b.get('bundle_format')!r} (re-run the NIDS notebook)")
        for src, d in (('bundle', b), ('metadata', m)):
            if d.get('deployable') is not True:
                r.append(f'{src}: deployable is not true')
            if d.get('network_signal_reliable') is not True:
                r.append(f'{src}: network_signal_reliable is not true')
            if d.get('fallback_mode') != NIDS_RELIABLE_MODE:
                r.append(f"{src}: fallback_mode is {d.get('fallback_mode')!r}")
        if m and m.get('model_version') not in (None, b.get('model_version')):
            r.append('metadata and bundle model versions differ')
        if b.get('feature_schema_fingerprint') != expected_fingerprint:
            r.append(f"schema fingerprint {b.get('feature_schema_fingerprint')!r} != {expected_fingerprint!r}")
        if m and m.get('schema_fingerprint') not in (None, expected_fingerprint):
            r.append('metadata schema fingerprint mismatch')
        if list(b.get('feature_columns') or []) != self.expected_features:
            r.append('bundle feature list/order differs from the framework contract')
        pipe = b.get('pipeline')
        if pipe is None or list(getattr(pipe, 'classes_', [])) != [0, 1]:
            r.append('model is missing or its class order is not [0 benign, 1 malicious]')
        if b.get('score_mode') not in ('supervised', 'fused'):
            r.append(f"unknown score mode {b.get('score_mode')!r}")
        if not _nids_spec_monotone(b.get('calibrator_spec')) and b.get('score_mode') == 'supervised':
            r.append('supervised calibrator missing or not monotone non-decreasing')
        if b.get('score_mode') == 'fused':
            f, n = b.get('fusion') or {}, b.get('novelty') or {}
            if not (0.0 <= float(f.get('w', -1)) <= 1.0) or not _nids_spec_monotone(f.get('spec')) \
                    or not _nids_spec_monotone(n.get('spec')) or n.get('pipeline') is None:
                r.append('fusion/novelty components incomplete or not monotone')
        thr = b.get('threshold')
        if thr is None or not (0.0 <= float(thr) <= 1.0):
            r.append(f'operating threshold invalid: {thr!r}')
        if manifest is not None and artifact_dir is not None:
            for fn in ('nids_inference_bundle.joblib', 'nids_run_metadata.json'):
                want = (manifest.get('sha256') or {}).get(fn)
                p = os.path.join(artifact_dir, fn)
                if not want or not os.path.exists(p) or _nids_sha256(p) != want:
                    r.append(f'{fn}: SHA-256 missing or does not match the artifact manifest (tampered or stale)')
        elif manifest is None:
            r.append('artifact manifest missing - integrity cannot be verified')

    # ---------- inference ----------
    def _matrix(self, rows):
        rows = [rows] if isinstance(rows, dict) else list(rows)
        out = []
        for row in rows:
            keys = list(row.keys())
            missing = [c for c in self.expected_features if c not in row]
            if missing:
                raise NIDSFeatureError(f'missing features: {missing}')
            present = [k for k in keys if k in self.expected_features]
            if present != self.expected_features:
                raise NIDSFeatureError('features are reordered relative to the contract')
            v = np.array([float(row[c]) for c in self.expected_features], dtype=np.float32)
            if not np.isfinite(v).all():
                raise NIDSFeatureError('non-finite feature value')
            out.append(v)
        return np.vstack(out)

    def _scores(self, X):
        b = self.bundle
        pipe = b['pipeline']
        raw = pipe.predict_proba(X)[:, list(pipe.classes_).index(1)]
        sup = np.clip(_nids_sigmoid_or_iso(b.get('calibrator_spec'), raw), 0, 1)
        out = {'raw_score': raw, 'supervised_threat_score': sup, 'threat_score': sup}
        if b.get('score_mode') == 'fused':
            nov = _nids_sigmoid_or_iso(b['novelty']['spec'], -b['novelty']['pipeline'].score_samples(X))
            w = float(b['fusion']['w'])
            out['novelty_threat_score'] = nov
            out['threat_score'] = np.clip(_nids_sigmoid_or_iso(b['fusion']['spec'], w * sup + (1 - w) * nov), 0, 1)
        return out

    def infer(self, rows):
        """The contract API. Unreliable -> threat_score None (never fabricated)."""
        base = {'threshold': self.bundle.get('threshold'), 'deployable': bool(self.bundle.get('deployable')),
                'network_signal_reliable': self.reliable, 'model_version': self.model_version,
                'feature_schema_fingerprint': self.feature_schema_fingerprint}
        n = 1 if isinstance(rows, dict) else len(rows)
        if not self.reliable:
            self._log('artifact not reliable: ' + '; '.join(self.reasons))
            return [{**base, 'threat_score': None, 'decision': -1, 'fallback_mode': NIDS_FALLBACK_MODE}] * n
        try:
            X = self._matrix(rows)
        except NIDSFeatureError as e:
            self._log(f'input refused: {e}')
            return [{**base, 'network_signal_reliable': False, 'threat_score': None, 'decision': -1,
                     'fallback_mode': NIDS_FALLBACK_MODE, 'refusal': str(e)}] * n
        sc = self._scores(X)
        thr = float(self.bundle['threshold'])
        return [{**base, 'threat_score': float(t), 'raw_score': float(r), 'decision': int(t >= thr),
                 'fallback_mode': NIDS_RELIABLE_MODE}
                for t, r in zip(sc['threat_score'], sc['raw_score'])]

    def _log(self, reason):
        if len(self.fallback_log) < 1000:
            self.fallback_log.append(reason)

    def network_risk_contribution(self, row):
        """Value handed to fusion: the threat score when reliable, else 0.0 (no
        contribution; the window is marked unavailable). Monotone in the score."""
        r = self.infer(row)[0]
        return (0.0, False) if r['threat_score'] is None else (float(r['threat_score']), True)


class GatedNetworkThreatDetector:
    """Drop-in for the legacy `network_threat_detector.predict_proba(row)` calls.
    Returns the reliable threat score, or 0.0 (no network contribution) when the
    adapter is unavailable or the row is refused. `available(row)` tells which."""

    def __init__(self, adapter, legacy_detector=None):
        self.adapter = adapter
        self.legacy_detector = legacy_detector
        self.reliable = adapter.reliable
        self.threshold = adapter.bundle.get('threshold') if adapter.reliable else None
        self.model_name = adapter.bundle.get('model_name', 'unavailable')

    def predict_proba(self, feature_row):
        return self.adapter.network_risk_contribution(feature_row)[0]

    def available(self, feature_row):
        return self.adapter.network_risk_contribution(feature_row)[1]

    def predict(self, feature_row):
        r = self.adapter.infer(feature_row)[0]
        return int(r['decision'] == 1)


def load_nids_adapter(artifact_dir):
    bundle, meta, manifest = {}, {}, None
    try:
        bundle = joblib.load(os.path.join(artifact_dir, 'nids_inference_bundle.joblib'))
    except Exception as e:
        print(f'[NIDS-ADAPTER] bundle could not be loaded ({type(e).__name__}: {e})')
    try:
        with open(os.path.join(artifact_dir, 'nids_run_metadata.json')) as f:
            meta = json.load(f)
    except Exception as e:
        print(f'[NIDS-ADAPTER] metadata could not be loaded ({type(e).__name__}: {e})')
    mp = os.path.join(artifact_dir, 'nids_artifact_manifest.json')
    if os.path.exists(mp):
        with open(mp) as f:
            manifest = json.load(f)
    return NIDSThreatAdapter(bundle if isinstance(bundle, dict) else {}, meta, manifest, artifact_dir)


# ===================================================================
# notebook cell [68] -> forecaster
#   provides: PoolDemandForecaster (definition only - not fitted here)
# ===================================================================
from sklearn.neural_network import MLPRegressor


class PoolDemandForecaster:
    """Forecast pool bits and estimate sessions-to-depletion.

    Uses a sliding window of `lookback` past readings (real temporal input).
    Neural path: Keras LSTM if TensorFlow is available, else sklearn MLP on the
    flattened window. ARIMA path as a classical baseline.

    The 80/20 temporal split is held out and scored (MAE in bits) against a
    persistence baseline, so the forecaster carries a reported error.
    """
    def __init__(self, lookback=5):
        self.lookback = lookback
        self.neural = None
        self.arima_fitted = None
        self._scaler = None
        self._backend = None
        self.holdout = None

    def _make_windows(self, series):
        X, y = [], []
        for i in range(self.lookback, len(series)):
            X.append(series[i - self.lookback:i])
            y.append(series[i, 0])
        return np.array(X), np.array(y)

    def _unscale_bits(self, scaled):
        # column 0 is total_available_bits; StandardScaler is affine per column
        return np.asarray(scaled, dtype=float) * self._scaler.scale_[0] + self._scaler.mean_[0]

    def _neural_predict_batch(self, X):
        if self._backend == 'lstm':
            return np.asarray(self.neural.predict(X, verbose=0)).ravel()
        return np.asarray(self.neural.predict(X.reshape(len(X), -1))).ravel()

    def fit_neural(self, df, verbose=False):
        raw = df[['total_available_bits', 'pool_depletion_rate']].values.astype(float)
        self._scaler = StandardScaler().fit(raw)
        series = self._scaler.transform(raw)
        X, y = self._make_windows(series)
        if len(X) < 8:
            raise ValueError('Not enough history to fit and validate the forecaster.')
        split = int(len(X) * 0.8)  # temporal split -- no shuffling
        if HAS_TENSORFLOW:
            from tensorflow import keras
            from tensorflow.keras import layers
            model = keras.Sequential([
                layers.Input(shape=(self.lookback, series.shape[1])),
                layers.LSTM(24), layers.Dense(12, activation='relu'),
                layers.Dense(1, activation='linear')])
            model.compile(optimizer='adam', loss='mse')
            model.fit(X[:split], y[:split], epochs=30, batch_size=8, verbose=0)
            self.neural = model; self._backend = 'lstm'
        else:
            model = MLPRegressor(hidden_layer_sizes=(24, 12), max_iter=800, random_state=SEED)
            model.fit(X[:split].reshape(split, -1), y[:split])
            self.neural = model; self._backend = 'mlp'

        # --- held-out evaluation (was previously computed and thrown away) ---
        Xte, yte = X[split:], y[split:]
        if len(Xte):
            pred_bits = self._unscale_bits(self._neural_predict_batch(Xte))
            true_bits = self._unscale_bits(yte)
            naive_bits = self._unscale_bits(Xte[:, -1, 0])   # persistence: repeat last reading
            mae = float(np.mean(np.abs(pred_bits - true_bits)))
            rmse = float(np.sqrt(np.mean((pred_bits - true_bits) ** 2)))
            mae_naive = float(np.mean(np.abs(naive_bits - true_bits)))
            self.holdout = {
                'n_test': int(len(Xte)), 'backend': self._backend,
                'mae_bits': mae, 'rmse_bits': rmse,
                'persistence_mae_bits': mae_naive,
                'skill_vs_persistence': float(1.0 - mae / mae_naive) if mae_naive > 0 else float('nan'),
            }
        if verbose:
            print(f'Demand forecaster fitted (backend={self._backend}, '
                  f'train={split}, test={len(Xte)})')
            if self.holdout:
                h = self.holdout
                print(f'  held-out MAE = {h["mae_bits"]:.1f} bits | RMSE = {h["rmse_bits"]:.1f} bits')
                print(f'  persistence MAE = {h["persistence_mae_bits"]:.1f} bits '
                      f'-> skill = {h["skill_vs_persistence"]:+.3f} '
                      f'({"beats" if h["skill_vs_persistence"] > 0 else "does NOT beat"} persistence)')
        return self

    def fit_arima(self, df, order=(1, 1, 1), verbose=False):
        from statsmodels.tsa.arima.model import ARIMA
        series = df['total_available_bits'].astype(float).values
        self.arima_fitted = ARIMA(series, order=order).fit()
        if verbose:
            print(f'ARIMA{order} fitted, AIC={self.arima_fitted.aic:.2f}')
        return self

    def _neural_predict_next(self, window_scaled):
        if self._backend == 'lstm':
            x = window_scaled.reshape(1, self.lookback, -1)
            return float(self.neural.predict(x, verbose=0)[0, 0])
        return float(self.neural.predict(window_scaled.reshape(1, -1))[0])

    def trend_slope(self, df, window=None):
        """Least-squares bits/session slope over a longer window than the
        two-point first-vs-last check, which a single tail up-tick can flip."""
        w = int(window or min(4 * self.lookback, len(df)))
        y = df.sort_values('session_id')['total_available_bits'].astype(float).values[-w:]
        if len(y) < 3:
            return 0.0
        return float(np.polyfit(np.arange(len(y)), y, 1)[0])

    def forecast_path(self, current_df, horizon=20, method='neural'):
        """Predicted pool level (bits) for the next `horizon` sessions."""
        recent = current_df.sort_values('session_id').tail(self.lookback)
        if len(recent) < self.lookback:
            return None
        if method == 'arima':
            return np.asarray(self.arima_fitted.forecast(steps=horizon), dtype=float)
        raw = recent[['total_available_bits', 'pool_depletion_rate']].values.astype(float)
        window = self._scaler.transform(raw)
        rate_est = float(window[:, 1].mean())
        path = []
        for _ in range(horizon):
            nxt = self._neural_predict_next(window[-self.lookback:])
            path.append(float(self._unscale_bits(nxt)))
            window = np.vstack([window, [nxt, rate_est]])
        return np.asarray(path, dtype=float)

    def predict_time_to_depletion(self, current_df, avg_bits_per_session=100,
                                  horizon=20, method='neural'):
        """Sessions until the pool falls below avg_bits_per_session.

        Returns an int when depletion occurs inside the horizon; otherwise a
        string that still reports the fitted trend, so a growing pool yields a
        measured statement rather than a bare 'N/A'."""
        path = self.forecast_path(current_df, horizon=horizon, method=method)
        if path is None:
            return 'N/A (insufficient history)'
        below = np.where(path < avg_bits_per_session)[0]
        if len(below):
            return int(below[0]) + 1
        slope = self.trend_slope(current_df)
        if slope >= 0:
            return f'>{horizon} (pool growing {slope:+.0f} bits/session)'
        return f'>{horizon} (declining {slope:.0f} bits/session, floor not reached)'


# ===================================================================
# notebook cell [70] -> scheduler
#   provides: AdaptiveScheduler
# ===================================================================
class AdaptiveScheduler:
    """Recommend a rekey interval (sessions) from threat + depletion signals."""
    def __init__(self, base_interval=10, min_interval=1, max_interval=40,
                 anomaly_sensitivity=1.0, depletion_urgency_window=5):
        self.base_interval = base_interval
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.anomaly_sensitivity = anomaly_sensitivity
        self.depletion_urgency_window = depletion_urgency_window

    @staticmethod
    def _ttd_value(time_to_depletion, default=999):
        """Coerce a possibly-string forecast into a numeric urgency value."""
        if isinstance(time_to_depletion, str):
            return default  # no depletion pressure
        return time_to_depletion

    def recommend_interval(self, anomaly_score, time_to_depletion):
        ttd = self._ttd_value(time_to_depletion)
        anomaly_factor = max(0.0, 1.0 - self.anomaly_sensitivity * anomaly_score)
        depletion_factor = min(1.0, ttd / self.depletion_urgency_window)
        interval = self.base_interval * anomaly_factor * depletion_factor
        if anomaly_score < 0.1 and ttd > self.depletion_urgency_window * 2:
            interval = self.base_interval * 1.5
        return int(np.clip(round(interval), self.min_interval, self.max_interval))


# ===================================================================
# notebook cell [74] -> decision
#   provides: DecisionEngine + cost-derived thresholds (anomaly_threshold_watch/alert/high)
# ===================================================================
class DecisionEngine:
    """Rule-based rekeying policy (pluggable via policy_fn)."""
    REKEY_NOW = 'REKEY_NOW'; SCHEDULE_REKEY = 'SCHEDULE_REKEY'
    DEFER = 'DEFER'; ALERT_ONLY = 'ALERT_ONLY'

    # Fix (2026-08-21b, STRUCTURALLY DEAD STATE): with the previous ladder,
    # SCHEDULE_REKEY could only fire when score < alert AND ttd > urgent AND
    # recommended_interval <= 2. But AdaptiveScheduler returns a SHORT interval
    # precisely when the score is HIGH or depletion is near - the two conditions
    # are mutually exclusive in practice, so the diagnostic reported
    # "0 rows qualified" on every window. The state was unreachable by
    # construction, not by chance.
    #
    # The ladder is now a proper three-band escalation over the score, so every
    # state owns a non-empty score interval:
    #     score >= high            -> REKEY_NOW      (act immediately)
    #     alert <= score < high    -> SCHEDULE_REKEY (act, but at the recommended interval)
    #     watch <= score < alert   -> ALERT_ONLY     (flag, do not consume a key)
    #     score < watch            -> DEFER          (nominal)
    # with pool depletion still able to force REKEY_NOW from any band.
    # ALERT_ONLY moved BELOW SchEDULE_REKEY because alerting is the cheaper,
    # weaker response - it belongs to the lower-confidence band.
    def __init__(self, anomaly_threshold_high=0.75, anomaly_threshold_alert=0.5,
                 anomaly_threshold_watch=None, depletion_urgent_sessions=2,
                 policy_fn=None):
        self.anomaly_threshold_high = anomaly_threshold_high
        self.anomaly_threshold_alert = anomaly_threshold_alert
        # default: halfway between 0 and the alert threshold, so the watch band
        # is always non-empty whatever the cost ratios produce
        self.anomaly_threshold_watch = (anomaly_threshold_alert / 2.0
                                        if anomaly_threshold_watch is None
                                        else anomaly_threshold_watch)
        self.depletion_urgent_sessions = depletion_urgent_sessions
        self.policy_fn = policy_fn
        self.decision_log = []
        assert 0 <= self.anomaly_threshold_watch < self.anomaly_threshold_alert \
               < self.anomaly_threshold_high <= 1, (
            f'Thresholds must satisfy 0 <= watch ({self.anomaly_threshold_watch:.3f}) '
            f'< alert ({self.anomaly_threshold_alert:.3f}) '
            f'< high ({self.anomaly_threshold_high:.3f}) <= 1, otherwise at least '
            f'one policy state is unreachable dead code.')

    @staticmethod
    def _ttd_num(ttd, default=999):
        return default if isinstance(ttd, str) else ttd

    def _rule_based_policy(self, anomaly_score, ttd, recommended_interval):
        ttd_n = self._ttd_num(ttd)
        if anomaly_score >= self.anomaly_threshold_high:
            return self.REKEY_NOW, 'anomaly above high threshold'
        if ttd_n <= self.depletion_urgent_sessions:
            return self.REKEY_NOW, 'pool depletion imminent'
        if anomaly_score >= self.anomaly_threshold_alert:
            return self.SCHEDULE_REKEY, 'anomaly in mid band - rekey at recommended interval'
        if anomaly_score >= self.anomaly_threshold_watch:
            return self.ALERT_ONLY, 'anomaly in watch band - flag without consuming a key'
        if recommended_interval <= 2:
            return self.SCHEDULE_REKEY, 'scheduler recommends short interval'
        return self.DEFER, 'conditions nominal'

    def decide(self, session_id, anomaly_score, time_to_depletion, recommended_interval):
        if self.policy_fn is not None:
            action = self.policy_fn(anomaly_score, time_to_depletion, recommended_interval)
            reason = 'learned policy'
        else:
            action, reason = self._rule_based_policy(anomaly_score, time_to_depletion, recommended_interval)
        result = {'session_id': session_id, 'anomaly_score': anomaly_score,
                  'time_to_depletion': time_to_depletion,
                  'recommended_interval': recommended_interval,
                  'action': action, 'reason': reason}
        self.decision_log.append(result)
        return result

    def to_dataframe(self):
        return pd.DataFrame(self.decision_log)


# Fix (cost-sensitive thresholds, corrected 2026-08-21): thresholds derived
# from an explicit cost ratio instead of hand-picked constants.
# threshold = C_FP / (C_FP + C_FN) is the cost-minimizing cutoff for a binary
# act/defer decision from a probability score.
#
# BUG THIS REPLACES: the previous version set
#     high  = C_FP_REKEY / (C_FP_REKEY + C_FN_REKEY) = 1/(1+5) = 0.167
#     alert = C_FP_ALERT / (C_FP_ALERT + C_FN_ALERT) = 1/(1+3) = 0.250
# i.e. high (0.167) < alert (0.250). Because _rule_based_policy tests
# `score >= high` FIRST, every score that could ever have reached the ALERT
# band had already been claimed by REKEY_NOW - ALERT_ONLY was unreachable
# dead code, and the QKD-only arm collapsed to REKEY_NOW/DEFER only.
#
# The ordering error was conceptual: an ALERT is a CHEAPER action than an
# immediate rekey, so its false-positive cost is LOWER, so it must fire at a
# LOWER score. C_FP_ALERT is now set below C_FP_REKEY, which puts the
# thresholds in the required order alert < high. An assertion makes any future
# re-inversion fail loudly instead of silently killing a policy state.
C_FN_REKEY = 5.0    # cost of missing an attack that should trigger REKEY_NOW
C_FP_REKEY = 1.0    # cost of an unnecessary immediate rekey (consumes a key)
C_FN_ALERT = 3.0    # cost of missing a signal worth flagging
C_FP_ALERT = 0.25   # cost of a nuisance alert (cheap: no key is consumed)

anomaly_threshold_high = C_FP_REKEY / (C_FP_REKEY + C_FN_REKEY)
anomaly_threshold_alert = C_FP_ALERT / (C_FP_ALERT + C_FN_ALERT)

assert anomaly_threshold_alert < anomaly_threshold_high, (
    f'Threshold inversion: ALERT ({anomaly_threshold_alert:.3f}) must be BELOW '
    f'REKEY_NOW ({anomaly_threshold_high:.3f}), otherwise ALERT_ONLY is '
    f'unreachable because the REKEY_NOW branch is tested first. Lower '
    f'C_FP_ALERT or raise C_FN_ALERT.')

print(f"[DecisionEngine] cost-derived thresholds: ALERT_ONLY >= {anomaly_threshold_alert:.3f} "
      f"(C_FP={C_FP_ALERT}, C_FN={C_FN_ALERT}) < REKEY_NOW >= {anomaly_threshold_high:.3f} "
      f"(C_FP={C_FP_REKEY}, C_FN={C_FN_REKEY})")

# The watch band (flag-only, no key consumed) is the cheapest response, so its
# threshold sits below the alert threshold. Cost of a pure log entry is taken as
# an order of magnitude below a nuisance alert.
C_FN_WATCH = 3.0
C_FP_WATCH = 0.05
anomaly_threshold_watch = C_FP_WATCH / (C_FP_WATCH + C_FN_WATCH)
print(f"[DecisionEngine] watch band  >= {anomaly_threshold_watch:.3f} "
      f"(C_FP={C_FP_WATCH}, C_FN={C_FN_WATCH})")


# ===================================================================
# notebook cell [93] -> rekeying
#   provides: RekeyingCommandInterface
# ===================================================================
class RekeyingCommandInterface:
    """Acts on decision-engine output against the KeyPool (KMS)."""
    # Fix (2026-09-12, REKEY == "RETRIEVE ANOTHER STORED KEY" + 64-BIT KEYS):
    # key_length now defaults to OPERATIONAL_KEY_BITS (256, was 64), and the
    # rekey itself is delegated to KeyLifecycleManager (Step 1B), which performs
    # ACTIVATE_NEW_KEY / REVOKE_OLD_KEY / EXPIRE_KEY / DESTROY_KEY explicitly and
    # falls back to RETRY_WHEN_POOL_EMPTY -> GENERATE_KEY_MATERIAL instead of
    # failing on the first empty-pool response. This class keeps its old role:
    # POLICY (which decisions become rekeys, and the key budget governor).
    def __init__(self, key_pool, key_length=None, budget_aware=True,
                 sessions_remaining=None, base_rekey_threshold=None,
                 lifecycle=None, connection_id='ai-control-plane',
                 key_ttl_sec=KEY_TTL_SEC, allow_replenish=False, max_retries=2):
        self.key_pool = key_pool
        self.key_length = int(OPERATIONAL_KEY_BITS if key_length is None else key_length)
        self.connection_id = connection_id
        # allow_replenish=False keeps the AI / baseline / online arms strictly
        # comparable: every arm replays the SAME fixed key inventory, so an arm
        # cannot win by minting extra key material mid-replay. Set True for an
        # operational run, where an empty pool legitimately triggers generation.
        self.lifecycle = lifecycle or KeyLifecycleManager(
            key_pool, key_length=self.key_length, key_ttl_sec=key_ttl_sec,
            max_retries=(max_retries if allow_replenish else 0),
            replenish_fn=(None if allow_replenish else (lambda target_bits, session_id=None: 0)))
        self.active_key = None
        self.pending_schedule = None
        self.event_log = []
        # Budget governor (see _passes_budget). sessions_remaining is the size
        # of the replay window; base_rekey_threshold defaults to the notebook's
        # cost-derived REKEY_NOW threshold.
        self.budget_aware = budget_aware
        self.sessions_remaining = sessions_remaining
        self.base_rekey_threshold = (anomaly_threshold_high if base_rekey_threshold is None
                                     else base_rekey_threshold)

    def _expire_active_key(self, at_session_id, at_time):
        """Retained for compatibility. The actual retirement (REVOKE -> EXPIRE
        -> DESTROY) is performed inside KeyLifecycleManager.rekey()."""
        if self.active_key is not None:
            self.active_key['expired_at_session'] = at_session_id
            self.active_key['expired_at_time'] = at_time

    def _execute_rekey(self, decision, current_session_id, trigger):
        request_time = time.time()
        base = {'session_id': current_session_id, 'timestamp': request_time,
                'trigger': trigger, 'action': decision['action'],
                'anomaly_score': decision.get('anomaly_score'),
                'time_to_depletion': decision.get('time_to_depletion')}
        result = self.lifecycle.rekey(connection_id=self.connection_id,
                                      session_id=current_session_id,
                                      key_length=self.key_length)
        if not result['ok']:
            self.event_log.append({**base, 'outcome': 'FAILED_NO_KEY_AVAILABLE',
                                   'latency_sec': None, 'key_id': None,
                                   'key_length_bits': self.key_length,
                                   'lifecycle_ops': '|'.join(result['ops']),
                                   'retries': result['retries'],
                                   'generated_bits': result['generated_bits']})
            return False
        self._expire_active_key(current_session_id, request_time)
        self.active_key = {'key_id': result['key_id'], 'key': result['key'],
                           'session_id': current_session_id,
                           'activated_at': result['activated_at'],
                           'expires_at': result['expires_at'],
                           'usage_policy': result['usage_policy']}
        self.event_log.append({**base, 'outcome': 'REKEYED',
                               'latency_sec': time.time() - request_time,
                               'key_id': result['key_id'],
                               'key_length_bits': result['key_length'],
                               'lifecycle_ops': '|'.join(result['ops']),
                               'retries': result['retries'],
                               'generated_bits': result['generated_bits']})
        return True

    # --- Fix (2026-08-21b, KEY BUDGET IGNORED) -----------------------------
    # Observed pathology: the AI arm issued 25 REKEY_NOW decisions against an
    # inventory that could fund 14, so 11 (44%) failed with
    # FAILED_NO_KEY_AVAILABLE - and the FUSED arm, once its probabilities were
    # calibrated, issued REKEY_NOW on 40 of 40 sessions. Neither is a detector
    # problem. The cost model behind the thresholds
    # (C_FN=5 * C_FP=1, 40% attack base rate) genuinely says "rekey almost
    # everything" - it simply has no notion that key material is FINITE. An
    # unnecessary rekey does not just cost 1; it can starve a later necessary
    # one, and the decision layer was blind to that.
    #
    # The governor makes scarcity explicit. When the pool can no longer fund a
    # rekey for every remaining session, the effective bar rises toward 1.0 in
    # proportion to the shortfall, so scarce key material is spent on the
    # highest-confidence sessions instead of the earliest ones. With a full
    # pool the behaviour is unchanged. Downgraded decisions are logged as
    # DEFERRED_KEY_SCARCITY rather than dropped, so the count is visible.
    def _affordable_rekeys(self):
        status = self.key_pool.get_pool_status()
        return int(status.get('total_available_bits', 0)) // max(1, self.key_length)

    def _scarcity(self):
        """0.0 = can fund every remaining session; 1.0 = nothing left."""
        if self.sessions_remaining is None or self.sessions_remaining <= 0:
            return 0.0
        return float(np.clip(1.0 - self._affordable_rekeys() / self.sessions_remaining, 0.0, 1.0))

    def _passes_budget(self, decision):
        if not self.budget_aware:
            return True
        score = decision.get('anomaly_score')
        if score is None:
            return True
        s = self._scarcity()
        if s <= 0.0:
            return True
        base = self.base_rekey_threshold
        effective = base + (1.0 - base) * s          # scarce pool -> higher bar
        return float(score) >= effective

    def handle_decision(self, decision, current_session_id):
        action = decision['action']
        if self.sessions_remaining is not None:
            self.sessions_remaining = max(0, self.sessions_remaining - 1)
        if action == 'REKEY_NOW' and not self._passes_budget(decision):
            self.event_log.append({'session_id': current_session_id, 'timestamp': time.time(),
                                   'trigger': 'budget', 'action': action,
                                   'outcome': 'DEFERRED_KEY_SCARCITY', 'latency_sec': None,
                                   'anomaly_score': decision.get('anomaly_score'),
                                   'time_to_depletion': decision.get('time_to_depletion')})
            return
        if action == 'REKEY_NOW':
            self._execute_rekey(decision, current_session_id, 'immediate')
        elif action == 'SCHEDULE_REKEY':
            due_at = current_session_id + max(1, decision.get('recommended_interval', 1))
            self.pending_schedule = due_at
            self.event_log.append({'session_id': current_session_id, 'timestamp': time.time(),
                                   'trigger': 'scheduled', 'action': action,
                                   'outcome': f'ARMED_FOR_SESSION_{due_at}', 'latency_sec': None,
                                   'anomaly_score': decision.get('anomaly_score'),
                                   'time_to_depletion': decision.get('time_to_depletion')})
        elif action == 'ALERT_ONLY':
            self.event_log.append({'session_id': current_session_id, 'timestamp': time.time(),
                                   'trigger': 'alert', 'action': action,
                                   'outcome': 'ALERT_RAISED_NO_REKEY', 'latency_sec': None,
                                   'anomaly_score': decision.get('anomaly_score'),
                                   'time_to_depletion': decision.get('time_to_depletion')})
        if self.pending_schedule is not None and current_session_id >= self.pending_schedule:
            self._execute_rekey(decision, current_session_id, 'scheduled_due')
            self.pending_schedule = None

    def to_dataframe(self):
        return pd.DataFrame(self.event_log)

    def summary(self):
        df = self.to_dataframe()
        if df.empty:
            return {}
        rekeyed = df[df['outcome'] == 'REKEYED']
        return {'total_events': len(df), 'successful_rekeys': len(rekeyed),
                'key_length_bits': self.key_length,
                'failed_rekeys_no_key': int((df['outcome'] == 'FAILED_NO_KEY_AVAILABLE').sum()),
                'deferred_key_scarcity': int((df['outcome'] == 'DEFERRED_KEY_SCARCITY').sum()),
                'alerts_raised': int((df['outcome'] == 'ALERT_RAISED_NO_REKEY').sum()),
                'avg_rekey_latency_sec': float(rekeyed['latency_sec'].mean()) if len(rekeyed) else None,
                'lifecycle_ops': dict(self.lifecycle.counters),
                'key_states': self.lifecycle.state_counts()}


# ===================================================================
# notebook cell [95] -> telemetry_logger
#   provides: SessionTelemetryLogger
# ===================================================================
class SessionTelemetryLogger:
    """Fuse feature_df + decisions + rekey events into one evaluation table."""

    # Fix (2026-08-21, METRIC NAME COLLISION): this class used to expose a
    # single key 'f1', printed as "Anomaly detector F1" - but it measures
    # `predicted_flag`, i.e. whether the POLICY chose to act (REKEY_NOW /
    # SCHEDULE_REKEY / ALERT_ONLY). A separate cell scored the SAME detector on
    # the SAME window as `score >= 0.5` and printed a different number under
    # the same name (0.780 vs 0.903). Two different quantities, one label.
    # They are now computed and reported separately and neither is called
    # "the" F1:
    #   policy_f1   - did the control plane ACT on attack sessions?
    #   detector_f1 - did the detector CLASSIFY attack sessions? (score >= t)
    # ROC-AUC is threshold-free and identical for both, so it stays single.
    DETECTOR_THRESHOLD = 0.5

    def __init__(self, feature_cols):
        self.feature_cols = feature_cols
        self.log = None

    def build(self, feature_df, decision_engine, rekeying_interface):
        decisions_df = decision_engine.to_dataframe()
        events_df = rekeying_interface.to_dataframe()
        if not events_df.empty:
            events_df = (events_df.assign(_is_rekey=lambda d: d['outcome'].eq('REKEYED'))
                         .sort_values('_is_rekey', ascending=False)
                         .drop_duplicates(subset='session_id', keep='first')
                         .drop(columns='_is_rekey'))
        log = feature_df.merge(decisions_df, on='session_id', how='inner', suffixes=('', '_decision'))
        log = log.merge(events_df, on='session_id', how='left', suffixes=('', '_event'))
        log['actual_attack'] = log[LABEL_COL].astype(bool)
        log['predicted_flag'] = log['action'].isin(['REKEY_NOW', 'SCHEDULE_REKEY', 'ALERT_ONLY'])
        log['did_rekey'] = log['outcome'].eq('REKEYED') if 'outcome' in log.columns else False
        self.log = log.reset_index(drop=True)
        return self.log

    def classification_metrics(self, detector_threshold=None):
        t = self.DETECTOR_THRESHOLD if detector_threshold is None else detector_threshold
        y_true = self.log['actual_attack'].astype(int).values
        y_policy = self.log['predicted_flag'].astype(int).values
        y_score = self.log['anomaly_score'].astype(float).values
        y_detector = (y_score >= t).astype(int)
        return {'n_sessions': len(self.log), 'n_attacks': int(y_true.sum()),
                'policy_f1': f1_score(y_true, y_policy, zero_division=0),
                'detector_f1': f1_score(y_true, y_detector, zero_division=0),
                'detector_threshold': t,
                'roc_auc': roc_auc_score(y_true, y_score) if len(set(y_true)) > 1 else float('nan')}

    def rekeying_latency_stats(self):
        rekeyed = self.log[self.log['did_rekey']]
        if rekeyed.empty:
            return {'n_rekeys': 0, 'mean_latency_sec': None}
        return {'n_rekeys': int(len(rekeyed)), 'mean_latency_sec': float(rekeyed['latency_sec'].mean())}

    def key_generation_rate(self, key_length):
        """Fresh key bits delivered per second of QUANTUM-CHANNEL time (Fix #19).

        WARNING (2026-08-21b, DOUBLE COUNTING): this is
        `n_rekeys * key_length / total_channel_time`. Both arms of every
        comparison in this notebook replay the SAME sessions, so
        total_channel_time is identical between them and this quantity is a
        pure rescaling of the rekey count - the AI's 64927.54 vs the baseline's
        18550.72 is exactly 14/4 = 3.5x, the same ratio as the rekey column.
        Reporting rekeys AND key rate as two results is reporting one result
        twice. Use unnecessary_rekey_rate() / key_bits_consumed() for axes that
        are genuinely independent of rekey count.
        """
        n_rekeys = int(self.log['did_rekey'].sum())
        total_time = self.log['channel_time_sec'].sum()
        return (n_rekeys * key_length) / total_time if total_time > 0 else 0.0

    def unnecessary_rekey_rate(self):
        """Share of executed rekeys that landed on a BENIGN session.

        Independent of how many rekeys were performed - a system that rekeys
        constantly scores badly here even though its raw rekey count (and
        therefore its 'key generation rate') looks impressive. This is the
        efficiency axis the key-rate metric cannot express.
        """
        rekeyed = self.log[self.log['did_rekey']]
        if rekeyed.empty:
            return float('nan')
        return float((~rekeyed['actual_attack']).mean())

    def key_bits_consumed(self, key_length):
        """Total key material spent from the pool (cost side of the ledger)."""
        return int(self.log['did_rekey'].sum()) * int(key_length)

    def cost_weighted_score(self, c_fn=5.0, c_fp=1.0):
        """Expected policy cost: c_fn per attack session left un-rekeyed plus
        c_fp per rekey spent on a benign session. Lower is better. This is the
        single number that trades coverage against waste, using the same cost
        ratio that produced the decision thresholds."""
        missed = int((self.log['actual_attack'] & ~self.log['did_rekey']).sum())
        wasted = int((~self.log['actual_attack'] & self.log['did_rekey']).sum())
        return float(c_fn * missed + c_fp * wasted)

    def attack_response_coverage(self):
        attacks = self.log[self.log['actual_attack']]
        if attacks.empty:
            return float('nan')
        return float(attacks['did_rekey'].mean())



# Restore the real builtin for anything that prints at runtime.
print = _real_print
del _real_print
