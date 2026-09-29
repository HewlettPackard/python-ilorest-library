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
"""Certificate fingerprint helpers for TLS certificate pinning.

Extracted from :mod:`redfish.rest.pqc` to keep that module focused on
PQC TLS group/mode handling and below the 600-line project limit.
"""

import hashlib
import logging

LOGGER = logging.getLogger(__name__)

#: Digest hex-lengths urllib3 accepts for ``assert_fingerprint`` (md5/sha1/sha256).
_FINGERPRINT_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def normalize_fingerprint(value):
    """Normalize a certificate fingerprint for urllib3 ``assert_fingerprint``.

    Certificate pinning authenticates the *specific* server certificate even when
    the chain is not verified (the common self-signed iLO case). This accepts the
    usual human formats — ``AA:BB:...``, spaces, mixed case, ``sha256:`` prefix —
    and returns a bare lowercase hex string.

    Args:
        value: A fingerprint string (md5/sha1/sha256 hex, optionally colon- or
            space-separated, with an optional ``<alg>:`` prefix).

    Returns:
        The normalized lowercase hex digest.

    Raises:
        ValueError: If *value* is empty or not a valid md5/sha1/sha256 hex digest.
    """
    if value is None:
        raise ValueError("fingerprint is required")
    text = str(value).strip().lower()
    # Strip an optional algorithm prefix like "sha256:".
    if ":" in text and not all(c in "0123456789abcdef:" for c in text):
        text = text.split(":", 1)[1]
    cleaned = text.replace(":", "").replace(" ", "").replace("-", "")
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("invalid fingerprint (non-hex characters): %r" % value)
    if len(cleaned) not in _FINGERPRINT_LENGTHS:
        raise ValueError("invalid fingerprint length %d; expected 32 (md5), 40 (sha1) or 64 (sha256)" % len(cleaned))

    # Warn on weak digest algorithms; SHA-256 is the only recommended choice.
    digest_name = _FINGERPRINT_LENGTHS[len(cleaned)]
    if digest_name == "md5":
        LOGGER.warning(
            "MD5 certificate fingerprint is cryptographically broken and "
            "should not be used for pinning. Use a SHA-256 fingerprint instead."
        )
    elif digest_name == "sha1":
        LOGGER.warning(
            "SHA-1 certificate fingerprint is deprecated for pinning. "
            "Use a SHA-256 fingerprint instead."
        )

    return cleaned


def fingerprint_from_der(der_bytes, hashname="sha256"):
    """Compute a certificate fingerprint from DER bytes.

    Useful for deriving the pin to configure from a certificate obtained out of
    band (e.g. ``openssl s_client`` output).

    Args:
        der_bytes: The DER-encoded certificate.
        hashname: Digest algorithm (``sha256`` recommended; ``sha1``/``md5`` accepted).

    Returns:
        The lowercase hex digest.

    Raises:
        ValueError: If *der_bytes* is empty or *hashname* is unsupported.
    """
    if not der_bytes:
        raise ValueError("der_bytes is required")
    if hashname not in _FINGERPRINT_LENGTHS.values():
        raise ValueError("unsupported hash %r; use sha256, sha1, or md5" % hashname)
    return hashlib.new(hashname, der_bytes).hexdigest()
