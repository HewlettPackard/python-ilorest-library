###
# Copyright 2020-2026 Hewlett Packard Enterprise, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

# -*- coding: utf-8 -*-
"""Post-Quantum Cryptography (PQC) TLS helpers for the transport layer.

This module builds an :class:`ssl.SSLContext` that *prefers* a hybrid
post-quantum key-exchange group while remaining fully backward compatible: on
runtimes whose OpenSSL build cannot select TLS groups, the helpers become a
no-op and the caller keeps urllib3's default context.

.. warning:: **Process-wide side effect at import time.**

   When ``ssl.SSLContext`` does not already expose a ``set_groups`` method
   (CPython < 3.15), this module installs a ctypes-based polyfill by assigning
   ``ssl.SSLContext.set_groups`` at module load time.  This is a **global**
   monkey-patch that affects *every* ``SSLContext`` instance in the process,
   including those created by third-party libraries.  A runtime sanity probe
   validates the CPython memory layout before installation; if the probe fails
   (debug builds, free-threaded builds, non-CPython interpreters) the polyfill
   is skipped and ``is_pqc_available()`` returns ``False``.

Design goals:

* **Self-contained** — the library must not depend on the CLI front-end, so the
  PQC catalogue and mode handling are duplicated here intentionally (kept in
  parity with ``ilorest.security.pqc``).
* **Safe by default** — ``hybrid`` mode only *adds* a PQC group to the offered
  list; servers that do not understand it simply negotiate a classical group.
  When the runtime cannot offer PQC groups the helper returns ``None`` so the
  transport behaves exactly as before.
* **Opt-in strictness** — ``strict`` mode raises :class:`PQCNotAvailableError`
  rather than silently downgrading.

The active mode is resolved from the ``ILOREST_PQC_MODE`` environment variable
(``off`` | ``hybrid`` | ``strict``), defaulting to ``hybrid``.
"""

import ctypes
import ctypes.util
import logging
import os
import ssl
import sys

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CPython ssl.SSLContext.set_groups polyfill
# ---------------------------------------------------------------------------
# CPython's stdlib ssl module does not expose SSL_CTX_set1_groups_list, so
# there is no public API to pin TLS groups for PQC.  This polyfill adds
# ssl.SSLContext.set_groups at import time by calling the OpenSSL C function
# directly through ctypes.  It is safe to call multiple times (idempotent).
#
# CPython internal layout (stable across 3.7-3.14):
#   _PySSLContext = { PyObject_HEAD, SSL_CTX *ctx, ... }
#   PyObject_HEAD on 64-bit = ob_refcnt (8 bytes) + ob_type (8 bytes) = 16 bytes
#   ⇒ SSL_CTX* is at id(ssl_ctx_obj) + 16
#
# The polyfill is installed once and ONLY patches ssl.SSLContext if the
# function is absent.  If SSL_CTX_set1_groups_list is not found (old OpenSSL)
# the patch silently does nothing and the existing "no set_groups" branch runs.


def _install_set_groups_polyfill():
    """Patch ssl.SSLContext.set_groups via ctypes if not already present.

    ``SSL_CTX_set1_groups_list`` is sometimes compiled as a macro that expands
    to ``SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST=92, 0, list)`` and may not
    appear as a named export in the DLL.  When the symbol is absent this
    polyfill calls ``SSL_CTX_ctrl`` directly with the numeric control code,
    which is stable across OpenSSL 1.1.1 through 3.x.

    Returns:
        bool: True if set_groups is available after this call.
    """
    if hasattr(ssl.SSLContext, "set_groups"):
        return True

    # Platform-specific candidate library names.
    if sys.platform == "win32":
        _candidates = ["libssl-3-x64.dll", "libssl-3.dll", "libssl.dll"]
    elif sys.platform == "darwin":
        _name = ctypes.util.find_library("ssl")
        _candidates = [_name] if _name else ["libssl.dylib", "libssl.3.dylib"]
    else:
        _name = ctypes.util.find_library("ssl")
        _candidates = [_name] if _name else []
        _candidates += ["libssl.so.3", "libssl.so.1.1", "libssl.so"]

    libssl = None
    for name in _candidates:
        if not name:
            continue
        try:
            libssl = ctypes.CDLL(name)
            LOGGER.debug("PQC polyfill: loaded %s.", name)
            break
        except OSError:
            continue

    if libssl is None:
        LOGGER.debug("PQC polyfill: could not load any OpenSSL library; group pinning unavailable.")
        return False

    # SSL_CTRL_SET_GROUPS_LIST = 92 is the macro constant used by
    # SSL_CTX_set1_groups_list — stable since OpenSSL 1.1.1.
    _SSL_CTRL_SET_GROUPS_LIST = 92
    _use_ctrl = False

    try:
        _raw = libssl.SSL_CTX_set1_groups_list
        _raw.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _raw.restype = ctypes.c_int
        LOGGER.debug("PQC polyfill: will use SSL_CTX_set1_groups_list.")
    except AttributeError:
        # The function is compiled inline; fall back to SSL_CTX_ctrl.
        try:
            _ctrl = libssl.SSL_CTX_ctrl
            _ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
            _ctrl.restype = ctypes.c_long
            _use_ctrl = True
            LOGGER.debug(
                "PQC polyfill: SSL_CTX_set1_groups_list not exported; "
                "falling back to SSL_CTX_ctrl(cmd=%d).",
                _SSL_CTRL_SET_GROUPS_LIST,
            )
        except AttributeError:
            LOGGER.debug(
                "PQC polyfill: neither SSL_CTX_set1_groups_list nor SSL_CTX_ctrl "
                "found; group pinning unavailable."
            )
            return False

    # CPython internal layout (stable 3.7–3.14):
    # _PySSLContext = { PyObject_HEAD, SSL_CTX *ctx, ... }
    # PyObject_HEAD = ob_refcnt (Py_ssize_t) + ob_type (void*) = 16 bytes on 64-bit
    _HEADER = ctypes.sizeof(ctypes.c_ssize_t) + ctypes.sizeof(ctypes.c_void_p)

    # Runtime sanity check: verify that the offset actually yields a valid
    # SSL_CTX* pointer.  We call SSL_CTX_get0_param (a safe, read-only getter
    # present since OpenSSL 1.0.2) on a throwaway context.  If the layout
    # assumption is wrong (debug build, free-threaded build, future CPython),
    # this will return NULL or crash — we catch both and bail out gracefully.
    try:
        _get0_param = libssl.SSL_CTX_get0_param
        _get0_param.argtypes = [ctypes.c_void_p]
        _get0_param.restype = ctypes.c_void_p

        _probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        _probe_ptr = ctypes.c_void_p.from_address(id(_probe_ctx) + _HEADER).value
        if _probe_ptr is None or _probe_ptr == 0:
            raise RuntimeError("extracted NULL SSL_CTX*")
        # SSL_CTX_get0_param must return a non-NULL X509_VERIFY_PARAM*.
        _verify_param = _get0_param(_probe_ptr)
        if _verify_param is None or _verify_param == 0:
            raise RuntimeError("SSL_CTX_get0_param returned NULL")
        del _probe_ctx, _probe_ptr, _verify_param
        LOGGER.debug("PQC polyfill: SSL_CTX* offset validated successfully.")
    except Exception as exc:
        LOGGER.debug(
            "PQC polyfill: SSL_CTX* memory-layout probe skipped — "
            "layout validation returned %s. Polyfill will not be installed "
            "(expected on debug, free-threaded, or non-CPython builds).",
            exc,
        )
        return False

    if _use_ctrl:
        def set_groups(self, groups):
            """Set the TLS supported-groups list via SSL_CTX_ctrl (polyfill)."""
            if isinstance(groups, str):
                groups = groups.encode("ascii")
            ctx_ptr = ctypes.c_void_p.from_address(id(self) + _HEADER).value
            if ctx_ptr is None:  # pragma: no cover
                raise ssl.SSLError("PQC polyfill: NULL SSL_CTX* in ssl.SSLContext.")
            # Keep buffer alive across the C call.
            buf = ctypes.create_string_buffer(groups)
            ret = _ctrl(ctx_ptr, _SSL_CTRL_SET_GROUPS_LIST, 0, buf)
            if ret != 1:
                raise ssl.SSLError(
                    "SSL_CTX_ctrl(SET_GROUPS_LIST, %r) failed (ret=%d); "
                    "group may not be supported by this OpenSSL build."
                    % (groups.decode("ascii", errors="replace"), int(ret))
                )
    else:
        def set_groups(self, groups):
            """Set the TLS supported-groups list via SSL_CTX_set1_groups_list (polyfill)."""
            if isinstance(groups, str):
                groups = groups.encode("ascii")
            ctx_ptr = ctypes.c_void_p.from_address(id(self) + _HEADER).value
            if ctx_ptr is None:  # pragma: no cover
                raise ssl.SSLError("PQC polyfill: NULL SSL_CTX* in ssl.SSLContext.")
            ret = _raw(ctx_ptr, groups)
            if ret != 1:
                raise ssl.SSLError(
                    "SSL_CTX_set1_groups_list(%r) failed (ret=%d); "
                    "group may not be supported by this OpenSSL build."
                    % (groups.decode("ascii", errors="replace"), int(ret))
                )

    ssl.SSLContext.set_groups = set_groups
    LOGGER.debug("PQC polyfill: ssl.SSLContext.set_groups installed.")
    return True


_install_set_groups_polyfill()

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
PQC_MODE_OFF = "off"
PQC_MODE_HYBRID = "hybrid"
PQC_MODE_STRICT = "strict"

VALID_MODES = (PQC_MODE_OFF, PQC_MODE_HYBRID, PQC_MODE_STRICT)

#: Environment variable that selects the PQC mode for the transport layer.
PQC_MODE_ENV_VAR = "ILOREST_PQC_MODE"
DEFAULT_MODE = PQC_MODE_HYBRID

# ---------------------------------------------------------------------------
# Algorithm catalogue (configuration, not hard-coded policy)
# ---------------------------------------------------------------------------
DEFAULT_KEM_GROUP = "X25519MLKEM768"
CLASSICAL_GROUPS = ("x25519", "secp256r1", "secp384r1")

# iLO7 Level-III (Security Category 3) KEM groups.
# iLO7 PQC uses the 768-bit ML-KEM hybrids with classical fallbacks.
ILO7_KEM_GROUPS = (
    "X25519MLKEM768",  # Primary Level-III hybrid (X25519 + ML-KEM-768)
    "SecP256r1MLKEM768",  # FIPS-compatible Level-III hybrid (P-256 + ML-KEM-768)
    "x25519",  # Classical fallback
    "secp256r1",  # Classical fallback (FIPS P-256)
    "secp384r1",  # Classical fallback (FIPS P-384)
)

# CNSA 2.0 Level-III explicit groups and sigalg for iLO7.
CNSA2_ILO7_KEM_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768")
CNSA2_ILO7_SIGALGS = ("mldsa65",)

# iLO8+ Level-V (Security Category 5) KEM groups.  IMPORTANT: strict CNSA 2.0
# on iLO8 is Security Category 5 / Level V and requires the **1024-bit** ML-KEM
# hybrids together with an **ML-DSA-87** certificate.  The 768-bit groups are
# rejected with a fatal TLS ``handshake_failure`` (alert 40).  Verified against
# an iLO8 whose cert reported ``sigalg: ML-DSA-87`` using:
#   openssl s_client -tls1_3 -sigalgs mldsa87 -groups MLKEM1024:SecP384r1MLKEM1024
# The list is ordered most-preferred (Level V) to least so a capable TLS stack
# negotiates the strongest mutually supported group.
ILO8_KEM_GROUPS = (
    "MLKEM1024",  # ML-KEM-1024 (CNSA 2.0 Level V, iLO8 strict)
    "SecP384r1MLKEM1024",  # P-384 + ML-KEM-1024 (FIPS-compatible Level V)
    "X25519MLKEM768",  # X25519 + ML-KEM-768 (Level III, iLO7 / hybrid)
    "SecP256r1MLKEM768",  # P-256 + ML-KEM-768 (Level III, FIPS-compatible)
    "x25519",  # Classical fallback
    "secp256r1",  # Classical fallback (FIPS P-256)
    "secp384r1",  # Classical fallback (FIPS P-384)
)

# CNSA 2.0 Level-V key-exchange groups and certificate signature required by a
# strict iLO8.  Kept as an explicit, colon-joinable catalogue for callers using a
# group/sigalg-capable TLS stack (pyOpenSSL, native OpenSSL 3.5, or ``s_client``).
# NOTE: CPython's stdlib ``ssl`` exposes neither ``set_groups`` nor ``set_sigalgs``,
# so a plain stdlib transport CANNOT satisfy strict iLO8 CNSA 2.0 even on OpenSSL
# 3.5 (its defaults offer only the 768-bit hybrid).  Use pyOpenSSL or drive the
# openssl CLI to pin these.
CNSA2_ILO8_KEM_GROUPS = ("MLKEM1024", "SecP384r1MLKEM1024")
CNSA2_ILO8_SIGALGS = ("mldsa87",)

# iLO generation thresholds for PQC feature gating (library-level).
_ILO_PQC_MIN_GEN = 7  # >= 7: PQC-TLS candidate (hybrid mode, Level III)
_ILO_STRICT_MIN_GEN = 8  # >= 8: strict PQC (Level V, iLO8+)

# First OpenSSL release whose *default* TLS group list already offers a hybrid
# post-quantum KEM (``X25519MLKEM768``).  From this version onward the transport
# negotiates a post-quantum key exchange with a *Level-III* CNSA iLO even though
# CPython's ``ssl`` module exposes no public API to pin the group list.  NOTE this
# is NOT sufficient for strict iLO8 (Level V), which needs the 1024-bit groups the
# defaults do not offer.
#
# Reason: ``ssl.SSLContext`` has no ``set_groups``/``set_sigalgs`` method and
# ``set_ecdh_curve`` only accepts a single classical EC curve name, so on stock
# CPython PQC support is driven entirely by the linked OpenSSL's default groups.
OPENSSL_PQC_DEFAULT_VERSION = (3, 5)


class PQCNotAvailableError(RuntimeError):
    """Raised when ``strict`` PQC is requested but cannot be provided."""


# ---------------------------------------------------------------------------
# Mode handling
# ---------------------------------------------------------------------------
def normalize_mode(mode):
    """Normalize a supplied PQC mode string.

    Args:
        mode: A mode string (case-insensitive), or ``None``.

    Returns:
        One of :data:`VALID_MODES`.

    Raises:
        ValueError: If *mode* is a non-empty string outside :data:`VALID_MODES`.
    """
    if mode is None:
        return PQC_MODE_OFF
    normalized = str(mode).strip().lower()
    if not normalized:
        return PQC_MODE_OFF
    if normalized not in VALID_MODES:
        raise ValueError("Invalid PQC mode %r; expected one of %s" % (mode, ", ".join(VALID_MODES)))
    return normalized


def resolve_mode_from_env(environ=None):
    """Resolve the active PQC mode from the environment.

    Args:
        environ: Optional mapping to read from (defaults to ``os.environ``).

    Returns:
        A normalized mode string; :data:`DEFAULT_MODE` when the variable is
        unset or blank, and :data:`PQC_MODE_OFF` when it holds an unrecognized
        value.
    """
    env = os.environ if environ is None else environ
    raw = env.get(PQC_MODE_ENV_VAR)
    if raw is None or not str(raw).strip():
        return DEFAULT_MODE
    try:
        return normalize_mode(raw)
    except ValueError:
        LOGGER.warning("Ignoring invalid %s=%r; disabling PQC.", PQC_MODE_ENV_VAR, raw)
        return PQC_MODE_OFF


# ---------------------------------------------------------------------------
# Feature detection
# ---------------------------------------------------------------------------
def is_pqc_available(context_factory=None):
    """Return ``True`` when the runtime can select TLS groups (PQC plumbing).

    Tests that ``set_groups`` is present AND that a PQC group name is
    recognised by the underlying OpenSSL build (not just that the method
    exists).

    Args:
        context_factory: Optional zero-arg callable returning an
            :class:`ssl.SSLContext`. Defaults to a standard client context.
    """
    try:
        ctx = (context_factory or ssl.create_default_context)()
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.debug("PQC feature detection failed to create context: %s", exc)
        return False
    setter = getattr(ctx, "set_groups", None)
    if setter is None:
        return False
    # Verify a PQC group is actually accepted (the polyfill or stdlib may exist
    # but the linked OpenSSL build might not know the group name).
    try:
        setter("X25519MLKEM768:x25519")
        return True
    except Exception as exc:
        LOGGER.debug("PQC feature detection: set_groups rejected test group (%s).", exc)
        return False


def openssl_supports_pqc_defaults(version_info=None):
    """Return ``True`` when the linked OpenSSL offers a hybrid PQC group by default.

    OpenSSL 3.5 added ``X25519MLKEM768`` to its default TLS group list. Because
    CPython's ``ssl`` module exposes no way to pin the group list explicitly
    (there is no ``set_groups`` and ``set_ecdh_curve`` rejects hybrid groups),
    this version check is the authoritative signal that a post-quantum key
    exchange will actually be *offered* on the wire.

    Args:
        version_info: Optional ``(major, minor, ...)`` tuple to test against
            (defaults to :data:`ssl.OPENSSL_VERSION_INFO`). Injectable for
            deterministic unit tests across OpenSSL builds.

    Returns:
        ``True`` when the effective OpenSSL version is >=
        :data:`OPENSSL_PQC_DEFAULT_VERSION`.
    """
    try:
        info = ssl.OPENSSL_VERSION_INFO if version_info is None else version_info
        return tuple(info[:2]) >= OPENSSL_PQC_DEFAULT_VERSION
    except Exception:  # pragma: no cover - defensive
        return False


# ---------------------------------------------------------------------------
# Group resolution
# ---------------------------------------------------------------------------
def resolve_groups(mode, kem_group=None, available=True, generation=None):
    """Resolve the ordered list of TLS groups to offer for *mode*.

    Args:
        mode: A PQC mode (normalized internally).
        kem_group: Optional override for the hybrid KEM group name. When given,
            it takes precedence over *generation*.
        available: Whether the runtime can select TLS groups.
        generation: Optional iLO generation. When *kem_group* is not supplied,
            the generation selects the appropriate KEM group list via
            :func:`kem_groups_for_generation` (iLO8+ → the Level-V
            ``MLKEM1024`` groups; iLO7 → the Level-III hybrids). This is
            essential for a strict iLO8, which rejects the Level-III-only
            default (``X25519MLKEM768``) with a fatal TLS ``handshake_failure``.

    Returns:
        An ordered list of group names (possibly empty for ``off``).

    Raises:
        PQCNotAvailableError: When ``strict`` is requested but *available* is
            ``False``.
    """
    mode = normalize_mode(mode)

    if mode == PQC_MODE_OFF:
        return []

    if not available:
        if mode == PQC_MODE_STRICT:
            raise PQCNotAvailableError(
                "PQC strict mode requested but this build cannot select "
                "post-quantum TLS groups (OpenSSL/Python lacks group support)."
            )
        LOGGER.debug("PQC unavailable; hybrid mode degrading to classical groups.")
        return list(CLASSICAL_GROUPS)

    # An explicit KEM-group override always wins.
    if kem_group and kem_group.strip():
        return [kem_group.strip()] + list(CLASSICAL_GROUPS)

    # Prefer the generation-specific list when the generation is known so that a
    # strict iLO8 offers the Level-V MLKEM1024 groups first instead of the
    # Level-III-only default (which the server rejects with handshake_failure).
    gen_groups = kem_groups_for_generation(generation)
    if gen_groups:
        return list(gen_groups)

    return [DEFAULT_KEM_GROUP] + list(CLASSICAL_GROUPS)


def _mode_from_generation(generation):
    """Return the recommended PQC mode for an iLO *generation* number.

    Args:
        generation: iLO generation (int, float, or str). ``None`` / unparseable
            values return :data:`DEFAULT_MODE`.

    Returns:
        One of :data:`PQC_MODE_OFF`, :data:`PQC_MODE_HYBRID`, :data:`PQC_MODE_STRICT`.
    """
    if generation is None:
        return DEFAULT_MODE
    try:
        gen = int(float(str(generation)))
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_MODE
    if gen >= _ILO_STRICT_MIN_GEN:
        return PQC_MODE_STRICT
    if gen >= _ILO_PQC_MIN_GEN:
        return PQC_MODE_HYBRID
    return PQC_MODE_OFF


def kem_groups_for_generation(generation):
    """Return the appropriate KEM group list for an iLO *generation*.

    Args:
        generation: iLO generation value.

    Returns:
        Tuple of group name strings:
        - iLO7  → :data:`ILO7_KEM_GROUPS`
        - iLO8+ → :data:`ILO8_KEM_GROUPS`
        - iLO<7 / unknown → empty tuple
    """
    if generation is None:
        return ()
    try:
        gen = int(float(str(generation)))
    except (TypeError, ValueError, OverflowError):
        return ()
    if gen >= _ILO_STRICT_MIN_GEN:
        return ILO8_KEM_GROUPS
    if gen >= _ILO_PQC_MIN_GEN:
        return ILO7_KEM_GROUPS
    return ()


# ---------------------------------------------------------------------------
# SSLContext construction
# ---------------------------------------------------------------------------
def build_pqc_ssl_context(
    cert_reqs="CERT_NONE", ca_certs=None, mode=None, kem_group=None, context_factory=None, ilo_generation=None
):
    """Build an ``SSLContext`` that offers PQC TLS groups, when possible.

    The returned context mirrors the transport's existing verification policy
    (no verification unless *ca_certs* is supplied with ``CERT_REQUIRED``), and
    additionally advertises a hybrid post-quantum key-exchange group.

    Args:
        cert_reqs: urllib3-style requirement (``"CERT_NONE"`` or
            ``"CERT_REQUIRED"``) reflecting the caller's current policy.
        ca_certs: Optional path to a CA bundle used when *cert_reqs* requires
            verification.
        mode: Optional explicit mode; if ``None``, derived from *ilo_generation*
            when supplied, otherwise from :func:`resolve_mode_from_env`.
        kem_group: Optional override for the hybrid KEM group name.
        context_factory: Optional zero-arg callable returning a base context
            (used for feature detection and construction; aids testing).
        ilo_generation: Optional iLO generation number.  When *mode* is ``None``
            this automatically selects ``hybrid`` for iLO7, ``strict`` for iLO8+,
            and ``off`` for iLO5/6, mirroring :class:`CryptoCapabilities`.

    Returns:
        A configured :class:`ssl.SSLContext`, or ``None`` when no PQC context is
        needed (mode ``off``, or ``hybrid`` where the transport default already
        offers PQC / cannot be improved). Returning ``None`` preserves the
        transport's default behavior exactly.

    Raises:
        PQCNotAvailableError: When ``strict`` mode is requested but neither an
            explicit group-setting API nor an OpenSSL build with default PQC
            groups is available (i.e. no post-quantum key exchange can be
            offered at all).
    """
    if mode is None:
        mode = _mode_from_generation(ilo_generation) if ilo_generation is not None else resolve_mode_from_env()
    else:
        mode = normalize_mode(mode)
    if mode == PQC_MODE_OFF:
        return None

    can_pin_groups = is_pqc_available(context_factory)
    default_pqc = openssl_supports_pqc_defaults()

    if not can_pin_groups:
        # No stdlib API to pin the TLS group list (the common CPython case).
        if default_pqc:
            # OpenSSL >= 3.5 already advertises X25519MLKEM768 by default, so a
            # post-quantum key exchange IS offered on the wire. hybrid keeps the
            # transport default (byte-for-byte unchanged); strict returns a
            # verify-policy context to affirm PQC support without downgrading.
            if mode == PQC_MODE_STRICT:
                context = (context_factory or ssl.create_default_context)()
                _apply_verify_policy(context, cert_reqs=cert_reqs, ca_certs=ca_certs)
                return context
            return None
        # OpenSSL too old to offer PQC by default and no way to pin groups.
        if mode == PQC_MODE_STRICT:
            raise PQCNotAvailableError(
                "PQC strict mode requested but this build can neither pin "
                "post-quantum TLS groups nor rely on OpenSSL default PQC groups "
                "(requires OpenSSL >= %d.%d)." % OPENSSL_PQC_DEFAULT_VERSION
            )
        LOGGER.debug("PQC unavailable; hybrid mode degrading to classical defaults.")
        return None

    # An explicit group-setting API is available: pin the ordered group list.
    groups = resolve_groups(mode, kem_group=kem_group, available=True, generation=ilo_generation)
    context = (context_factory or ssl.create_default_context)()
    _apply_verify_policy(context, cert_reqs=cert_reqs, ca_certs=ca_certs)
    _apply_groups(context, groups, strict=(mode == PQC_MODE_STRICT))
    return context


def _apply_verify_policy(context, cert_reqs="CERT_NONE", ca_certs=None):
    """Apply the transport's certificate-verification policy to *context*."""
    if cert_reqs == "CERT_REQUIRED":
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if ca_certs:
            try:
                context.load_verify_locations(cafile=ca_certs)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug("Could not load CA file %r: %s", ca_certs, exc)
    else:
        # iLO endpoints are typically reached by IP with self-signed certs; the
        # transport historically does not verify unless CA data is provided.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE


def _apply_groups(context, groups, strict=False):
    """Apply the resolved *groups* to *context* using ``set_groups``."""
    if not groups:
        return
    grouplist = ":".join(groups)
    setter = getattr(context, "set_groups", None)
    if setter is None:
        if strict:
            raise PQCNotAvailableError("PQC strict mode requested but the TLS context lacks group selection.")
        LOGGER.debug("Context lacks set_groups; leaving classical defaults.")
        return
    try:
        setter(grouplist)
        LOGGER.debug("Applied TLS groups: %s", grouplist)
    except Exception as exc:
        if strict:
            raise PQCNotAvailableError("Failed to apply PQC TLS groups %r: %s" % (grouplist, exc))
        LOGGER.debug("Failed to apply PQC groups %r (%s); using classical defaults.", grouplist, exc)


# ---------------------------------------------------------------------------
# Certificate pinning helpers (canonical impl in pqc_fingerprint.py)
# ---------------------------------------------------------------------------
from redfish.rest.pqc_fingerprint import (  # noqa: F401  (re-exported)
    normalize_fingerprint,
    fingerprint_from_der,
)
