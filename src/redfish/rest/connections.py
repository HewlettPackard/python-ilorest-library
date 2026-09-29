###
# Copyright 2020 Hewlett Packard Enterprise, Inc. All rights reserved.
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
"""All Connections for interacting with REST."""

import gzip
import json
import logging
import time

import urllib3
from urllib3 import PoolManager, ProxyManager
from urllib3.exceptions import DecodeError, MaxRetryError
from urllib3.exceptions import SSLError as Urllib3SSLError

try:
    urllib3.disable_warnings()
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    pass

import six
from six import BytesIO
from six.moves.urllib.parse import urlencode, urlparse

from redfish.hpilo.risblobstore2 import (
    Blob2OverrideError,
    Blob2SecurityError,
    BlobStore2,
    HpIloError,
)
from redfish.hpilo.rishpilo import HpIloChifPacketExchangeError
from redfish.rest.containers import RestRequest, RestResponse, RisRestResponse
from redfish.rest import pqc
from redfish.security_masking import SecurityMasker

# ---------End of imports---------


# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class RetriesExhaustedError(Exception):
    """Raised when retry attempts have been exhausted."""

    pass


class VnicNotEnabledError(Exception):
    """Raised when retry attempts have been exhausted when VNIC is not enabled."""

    pass


class VnicTlsHandshakeError(Exception):
    """Raised when a TLS handshake failure prevents reaching the VNIC endpoint.

    This is distinct from :class:`VnicNotEnabledError`: the VNIC is present and
    the TCP connection succeeds, but the TLS negotiation fails — most commonly
    because iLO8 is in CNSA 2.0 (Level V) strict mode and requires
    ``MLKEM1024`` / ``SecP384r1MLKEM1024`` KEM groups that the client's OpenSSL
    build does not offer by default.
    """

    pass


class DecompressResponseError(Exception):
    """Raised when decompressing the response failed."""

    pass


class InvalidCredentialsError(Exception):
    """Raised when invalid credentials have been provided."""

    pass


class InvalidCertificateError(Exception):
    """Raised when a invalid certificate has been provided."""

    pass


class ChifDriverMissingOrNotFound(Exception):
    """Raised when CHIF driver is missing or not found."""

    pass


class SecurityStateError(Exception):
    """Raised when there is a strict security state without authentication."""

    pass


class OneTimePasscodeError(Exception):
    """Raised when OTP is sent to the registered email."""

    pass


class TokenExpiredError(Exception):
    """Raised when OTP entered has expired."""

    pass


class UnauthorizedLoginAttemptError(Exception):
    """Raised when Login is Unauthorized"""

    pass


class HttpConnection(object):
    """HTTP connection capable of authenticating with HTTPS and Http/Socks Proxies

    :param base_url: The URL to make HTTP calls against
    :type base_url: str
    :param \\**client_kwargs: Arguments to pass to the connection initialization. These are"
        "passed to a urllib3 `PoolManager <https://urllib3.readthedocs.io/en/latest/reference/"
        "index.html?highlight=PoolManager#urllib3.PoolManager>`_. All arguments that can be passed to "
        "a PoolManager are valid arguments."
    """

    def __init__(self, base_url, cert_data, **client_kwargs):
        self._conn = None
        self.base_url = base_url
        # Default values for connection properties
        self._connection_properties = {
            "timeout": urllib3.util.Timeout(connect=4800, read=4800),
            "retries": urllib3.util.Retry(connect=50, read=50, redirect=50),
        }
        self._connection_properties.update(client_kwargs)
        if cert_data:
            if ("cert_file" in cert_data and cert_data["cert_file"]) or (
                "ca_certs" in cert_data and cert_data["ca_certs"]
            ):
                self._connection_properties.update({"ca_cert_data": cert_data})
        # Optional certificate pinning: authenticate the *specific* server cert by
        # its SHA-256 (or sha1/md5) fingerprint even when the chain is not verified.
        # This is the secure way to trust a self-signed iLO certificate (e.g. a
        # CNSA 2.0 ML-DSA-87 cert) without an enterprise CA.
        self._assert_fingerprint = None
        pin = None
        if cert_data and isinstance(cert_data, dict):
            pin = cert_data.get("fingerprint") or cert_data.get("assert_fingerprint")
        pin = pin or self._connection_properties.pop("assert_fingerprint", None)
        if pin:
            try:
                self._assert_fingerprint = pqc.normalize_fingerprint(pin)
            except ValueError as exc:
                LOGGER.warning("Ignoring invalid certificate fingerprint pin: %s", exc)
        # Optional iLO generation hint: drives automatic PQC mode selection
        # (hybrid for iLO7, strict for iLO8+, off for iLO5/6).
        _gen = self._connection_properties.pop("ilo_generation", None)
        if _gen is not None:
            self._connection_properties["ilo_generation"] = _gen
        self._proxy = self._connection_properties.pop("proxy", None)
        self.session_key = self._connection_properties.pop("session_key", None)
        self.session_location = self._connection_properties.pop("session_location", None)
        self.log_dir = self._connection_properties.pop("log_dir", None)
        self._init_connection()

    @property
    def proxy(self):
        """The proxy, if any."""
        return self._proxy

    @proxy.setter
    def proxy(self, proxy):
        """set the proxy"""
        self._proxy = proxy

    def _init_connection(self):
        """Function for initiating connection with remote server"""
        # For certificate-based authentication, we don't verify the server's certificate
        # We're providing our client certificate to authenticate TO the server
        cert_reqs = "CERT_NONE"

        if self._connection_properties.get("ca_cert_data"):
            LOGGER.info("Using certificate-based authentication.")
            ca_cert_data = self._connection_properties.pop("ca_cert_data")

            # Extract certificate files
            cert_file = ca_cert_data.get("cert_file")
            key_file = ca_cert_data.get("key_file")
            ca_certs = ca_cert_data.get("ca_certs")

            # Add client certificate and key for authentication
            if cert_file:
                self._connection_properties["cert_file"] = cert_file
            if key_file:
                self._connection_properties["key_file"] = key_file

            # If CA certs provided, use them to verify server certificate
            if ca_certs:
                self._connection_properties["ca_certs"] = ca_certs
                cert_reqs = "CERT_REQUIRED"
                LOGGER.info("Server certificate verification enabled with provided CA.")

        # Resolve an SSLContext to use for the connection. An explicit caller
        # supplied ``ssl_context`` always wins; otherwise a PQC-preferring
        # context may be built (hybrid by default). A ``None`` result preserves
        # the transport's historical behavior (urllib3 builds its own context).
        ssl_context = self._resolve_ssl_context(cert_reqs)
        manager_kwargs = dict(self._connection_properties)
        if ssl_context is not None:
            manager_kwargs["ssl_context"] = ssl_context
        # Certificate pinning: urllib3 verifies the peer cert fingerprint and
        # raises SSLError on mismatch, authenticating the server even under
        # CERT_NONE. This closes the MITM gap for self-signed iLO certificates.
        if self._assert_fingerprint:
            manager_kwargs["assert_fingerprint"] = self._assert_fingerprint
            LOGGER.info("Certificate pinning enabled (assert_fingerprint).")

        if self.proxy:
            if self.proxy.startswith("socks"):
                LOGGER.info("Initializing a SOCKS proxy.")
                http = SOCKSProxyManager(self.proxy, cert_reqs=cert_reqs, maxsize=50, **manager_kwargs)
            else:
                LOGGER.info("Initializing a HTTP proxy.")
                http = ProxyManager(self.proxy, cert_reqs=cert_reqs, maxsize=50, **manager_kwargs)
        else:
            LOGGER.info("Initializing no proxy.")

            http = PoolManager(cert_reqs=cert_reqs, maxsize=50, **manager_kwargs)

        self._conn = http.request

    def _resolve_ssl_context(self, cert_reqs):
        """Resolve the SSLContext for the connection.

        An explicit caller-supplied ``ssl_context`` (passed through
        ``client_kwargs``) takes precedence. Otherwise a PQC-preferring context
        is built via :func:`redfish.rest.pqc.build_pqc_ssl_context`. An optional
        ``pqc_mode`` keyword (also passed through ``client_kwargs``) overrides
        the environment-driven mode for this connection.

        :param cert_reqs: urllib3-style requirement reflecting the current
            verification policy (``"CERT_NONE"`` or ``"CERT_REQUIRED"``).
        :type cert_reqs: str
        :returns: An :class:`ssl.SSLContext`, or ``None`` to keep the transport
            default behavior.
        """
        explicit = self._connection_properties.pop("ssl_context", None)
        if explicit is not None:
            # Consume any pqc_mode so it never leaks into the PoolManager kwargs.
            self._connection_properties.pop("pqc_mode", None)
            return explicit

        pqc_mode = self._connection_properties.pop("pqc_mode", None)
        ilo_generation = self._connection_properties.pop("ilo_generation", None)
        try:
            return pqc.build_pqc_ssl_context(
                cert_reqs=cert_reqs,
                ca_certs=self._connection_properties.get("ca_certs"),
                mode=pqc_mode,
                ilo_generation=ilo_generation,
            )
        except pqc.PQCNotAvailableError:
            # strict mode explicitly requested but unavailable: surface to caller.
            raise
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.debug("Could not build PQC SSL context; using transport defaults: %s", exc)
            return None

    def rest_request(self, path, method="GET", args=None, body=None, headers=None):
        """Format and do HTTP Rest request

        :param path: The URI path to perform the operation on.
        :type path: str
        :param method: method to perform on the path.
        :type method: str
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param body: body payload to include in the request if needed.
        :type body: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        # TODO: Need to remove redfish.dmtf.org calls from here, add to their own HttpConnection
        files = None
        request_args = {}
        if isinstance(path, bytes):
            path = path.decode("utf-8")
            external_uri = True if "redfish.dmtf.org" in path else False
        else:
            external_uri = True if "redfish.dmtf.org" in path else False
        headers = {} if external_uri else headers
        reqpath = path.replace("//", "/") if not external_uri else path

        if body is not None:
            if body and isinstance(body, list) and isinstance(body[0], tuple):
                files = body
                body = None
            elif isinstance(body, (dict, list)):
                headers["Content-Type"] = "application/json"
                body = json.dumps(body)
            elif not files:
                headers["Content-Type"] = "application/octet-stream"

            if method == "PUT":
                resp = self.rest_request(method="HEAD", path=path, headers=headers)

                try:
                    if resp.getheader("content-encoding") == "gzip":
                        buf = BytesIO()
                        gfile = gzip.GzipFile(mode="wb", fileobj=buf)

                        try:
                            gfile.write(str(body).encode("utf-8") if six.PY3 else str(body))
                        finally:
                            gfile.close()

                        compresseddata = buf.getvalue()
                        if compresseddata:
                            data = bytearray()
                            data.extend(memoryview(compresseddata))
                            body = data
                except BaseException as excp:
                    LOGGER.error("Error occur while compressing body: %s", excp)
                    raise

        if args:
            if method == "GET":
                reqpath += "?" + urlencode(args)
            elif method == "PUT" or method == "POST" or method == "PATCH":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urlencode(args)

        # TODO: ADD to the default headers?
        if headers is not None:
            headers["Accept-Encoding"] = "gzip"
        restreq = RestRequest(path, method, data=files if files else body, url=self.base_url)

        if LOGGER.isEnabledFor(logging.DEBUG):
            try:
                logbody = None
                if restreq.body:
                    if restreq.body[0] == "{":
                        logbody = restreq.body
                    else:
                        raise KeyError()
                if restreq.method in ["POST", "PATCH"]:
                    debugjson = json.loads(restreq.body)
                    debugjson_masked = SecurityMasker.mask_simple_body(debugjson)
                    logbody = json.dumps(debugjson_masked)
                    logbody = logbody.replace("\\\\", "\\")
                headers_masked = SecurityMasker.mask_http_headers(headers)
                LOGGER.debug(
                    "HTTP REQUEST: %s\n\tPATH: %s\n\t" "HEADERS: %s\n\tBODY: %s",
                    restreq.method,
                    restreq.path,
                    headers_masked,
                    logbody,
                )
            except:
                LOGGER.debug(
                    "HTTP REQUEST: %s\n\tPATH: %s\n\tBODY: %s",
                    restreq.method,
                    restreq.path,
                    "binary body",
                )

        inittime = time.time()
        reqfullpath = self.base_url + reqpath if not external_uri else reqpath

        # To ensure we don't have unicode/string merging issues in httplib of Python 2
        if isinstance(reqfullpath, six.text_type):
            reqfullpath = str(reqfullpath)

        if headers:
            request_args["headers"] = headers
        if files:
            request_args["fields"] = files
        else:
            request_args["body"] = body
        try:
            resp = self._conn(method, reqfullpath, **request_args)
        except MaxRetryError as exc:
            vnic_url = "16.1.15.1"
            if reqfullpath.find(vnic_url) != -1:
                if isinstance(getattr(exc, "reason", None), Urllib3SSLError):
                    raise VnicTlsHandshakeError() from exc
                raise VnicNotEnabledError()
            raise RetriesExhaustedError()
        except DecodeError:
            raise DecompressResponseError()

        endtime = time.time()
        LOGGER.info("Response Time to %s: %s seconds.", restreq.path, str(endtime - inittime))

        restresp = RestResponse(restreq, resp)
        #        if restresp.request.body:
        #            respbody = restresp.read
        #            respbody = respbody.replace("\\\\", "\\")

        if LOGGER.isEnabledFor(logging.DEBUG):
            headerstr = ""
            if restresp is not None:
                respheader = restresp.getheaders()
                for kiy, headerval in respheader.items():
                    headerstr += "\t" + kiy + ": " + headerval + "\n"
                try:
                    headerstr_masked = SecurityMasker.mask_http_headers(headerstr)
                    response_body = SecurityMasker.mask_simple_body(restresp.read)

                    LOGGER.debug(
                        "HTTP RESPONSE for %s:\nCode:%s\nHeaders:" "\n%s\nBody Response of %s: %s",
                        restresp.request.path,
                        str(restresp._http_response.status) + " " + restresp._http_response.reason,
                        headerstr_masked,
                        restresp.request.path,
                        response_body,
                    )
                except:
                    LOGGER.debug("HTTP RESPONSE:\nCode:%s", restresp)
            else:
                LOGGER.debug("HTTP RESPONSE: No HTTP Response obtained")

        return restresp

    def cert_login(self):
        """Login using a certificate."""
        resp = self.rest_request("/html/login_cert.html", "GET")
        if resp.status == 200 or resp.status == 201:
            token = resp.getheader("X-Auth-Token")
            location = resp.getheader("Location")
        else:
            raise InvalidCertificateError("")

        return token, location


class Blobstore2Connection(object):
    """A connection for communicating locally with HPE servers

    :param \\**conn_kwargs: Arguments to pass to the connection initialization.

    Possible arguments for *\\**conn_kwargs* include:

    :username: The username to login with
    :password: The password to login with
    """

    _http_vsn_str = "HTTP/1.1"
    blobstore_headers = {"Accept": "*/*", "Connection": "Keep-Alive"}

    def __del__(self):
        """Clear channel"""
        self._conn = None

    def __init__(self, **conn_kwargs):
        self._conn = None
        self.base_url = "blobstore://."
        self._connection_properties = dict(conn_kwargs)
        self.session_key = self._connection_properties.pop("sessionid", None)
        # NOTE: _init_connection is deferred to the first rest_request call
        # (lazy initialization).  This avoids opening a CHIF channel during
        # session-cache restore (uncache_rmc) when the caller — typically a
        # raw command — will immediately create its own BlobStore2 instance
        # and never use this connection object.  Eager init costs ~1–2 s per
        # invocation because BlobStore2.__init__ opens a CHIF channel.

    def _init_connection(self, **kwargs):
        """Initiate blobstore connection"""
        # mixed security modes require a password at all times
        username = kwargs.get("username", "nousername")
        if isinstance(username, bytes):
            username = username.decode("utf-8")
        password = kwargs.get("password", "nopassword")
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        log_dir = kwargs.get("log_dir", "")
        # Optional pre-computed security state (get_security_state() enum: 1=factory,
        # 3=production, 4/5/6=high-security). When supplied by a caller that already learned
        # the mode before login, it lets us skip the in-band ChifVerifyCredentials() and
        # get_security_state() round-trips on the factory fast-path. None => probe in-band.
        security_state_hint = kwargs.get("security_state")
        try:
            correctcreds = BlobStore2.initializecreds(
                username=username, password=password, log_dir=log_dir, security_state=security_state_hint
            )
            bs2 = BlobStore2(log_dir=log_dir, username=username, password=password)
            if not correctcreds:
                # initializecreds() has already made the invalid-credential decision: an
                # in-band AccessDenied that it could not attribute to factory vs production
                # (ChifIsSecurityRequired() reports 0 for both). Resolve it now -- probing
                # the granular security state as late as possible, only at this point where
                # we must either fail with invalid credentials or ignore it in factory mode.
                self._resolve_unconfirmed_credentials(bs2, security_state_hint)
        except Blob2SecurityError:
            raise InvalidCredentialsError(0)
        except HpIloChifPacketExchangeError as excp:
            LOGGER.info("Exception: %s", str(excp))
            raise ChifDriverMissingOrNotFound()
        except Exception as excp:
            if str(excp) == "chif":
                raise ChifDriverMissingOrNotFound()
            else:
                raise
        else:
            self._conn = bs2

    def _resolve_unconfirmed_credentials(self, bs2, security_state=None):
        """Resolve credentials that could not be confirmed during in-band login.

        Called only after the invalid-credential decision has been made (initializecreds
        returned False). The granular security state decides the outcome:

        * Factory mode (state 1): CCSE-148119 -- ChifVerifyCredentials() returns AccessDenied
          even for VALID credentials, so ignore the failed pre-check and defer authentication
          to the authenticated request (no change from previous behaviour).
        * Production mode (state 3): in-band verification is reliable, so a wrong password is
          real -- fail with InvalidCredentialsError.
        * Any other (credential-required) state: raise SecurityStateError.

        The security state is taken from the ``security_state`` hint when the caller has
        already determined it (skipping the extra ``get_security_state()`` round-trip); it is
        only probed in-band when no valid hint is supplied. This keeps the probe "as late as
        possible" while allowing a faster login when the mode is already known.

        :param bs2: an initialised BlobStore2 whose security_state can be queried.
        :param security_state: optional pre-computed security state (1/3/4/5/6). When None or
            an unrecognised value, the state is probed in-band via ``bs2.get_security_state()``.
        :raises InvalidCredentialsError: in production mode with a wrong password.
        :raises SecurityStateError: when the security mode requires credentials that were
            not accepted.
        """
        if security_state not in (1, 3, 4, 5, 6):
            security_state = int(bs2.get_security_state())
        if security_state == 1:
            LOGGER.debug(
                "Factory mode: in-band verification is unreliable; ignoring the failed "
                "pre-check and deferring authentication to the authenticated request."
            )
            return
        if security_state == 3:
            raise InvalidCredentialsError(0)
        raise SecurityStateError(security_state)

    def rest_request(self, path="", method="GET", args=None, body=None, headers=None):
        """Rest request for blobstore client

        :param path: The URI path to perform the operation on.
        :type path: str
        :param method: method to perform on the path.
        :type method: str
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param body: body payload to include in the request if needed.
        :type body: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        # Lazy initialization: open the CHIF channel on first use rather than
        # in __init__.  This prevents an unnecessary BlobStore2 open/close
        # cycle when the connection object is built during session-cache
        # restore but the caller (e.g. a raw command) never actually sends a
        # request through it.
        if self._conn is None:
            self._init_connection(**self._connection_properties)

        # default headers if not passed in - otherwise will throw on .update call
        if headers is None:
            headers = {}
        else:
            headers.update(Blobstore2Connection.blobstore_headers)
        if isinstance(path, bytes):
            path = path.decode("utf-8")
        reqpath = path.replace("//", "/")

        oribody = body
        if body is not None:
            if isinstance(body, (dict, list)):
                headers["Content-Type"] = "application/json"
                if isinstance(body, bytes):
                    body = body.decode("utf-8")
                body = json.dumps(body)
            elif isinstance(body, bytes):
                headers["Content-Type"] = "application/octet-stream"
                body = bytearray(body)
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urlencode(body)

            if method == "PUT":
                resp = self.rest_request(path=path, headers=headers)

                try:
                    if resp.getheader("content-encoding") == "gzip":
                        buf = BytesIO()
                        gfile = gzip.GzipFile(mode="wb", fileobj=buf)

                        try:
                            gfile.write(str(body).encode("utf-8") if six.PY3 else str(body))
                        finally:
                            gfile.close()

                        compresseddata = buf.getvalue()
                        if compresseddata:
                            data = bytearray()
                            data.extend(memoryview(compresseddata))
                            body = data
                except BaseException as excp:
                    LOGGER.error("Error occur while compressing body: %s", excp)
                    raise

            headers["Content-Length"] = len(body)

        if args:
            if method == "GET":
                reqpath += "?" + urlencode(args)
            elif method == "PUT" or method == "POST" or method == "PATCH":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urlencode(args)

        str1 = "{} {} {}\r\n".format(method, reqpath, Blobstore2Connection._http_vsn_str)
        str1 += "Host: \r\n"
        str1 += "Accept-Encoding: gzip\r\n"
        for header, value in headers.items():
            str1 += "{}: {}\r\n".format(header, value)

        str1 += "\r\n"

        if body and len(body) > 0:
            if isinstance(body, bytearray):
                str1 = bytearray(str1.encode("utf-8")) + body
            else:
                # if isinstance(body, bytes):
                #    body = body.decode("utf-8")
                str1 += body

        if not isinstance(str1, bytearray):
            str1 = bytearray(str1.encode("utf-8"))

        if LOGGER.isEnabledFor(logging.DEBUG):
            try:
                logbody = None
                if body:
                    if body[0] == "{":
                        logbody = body
                    else:
                        raise
                if method in ["POST", "PATCH"]:
                    debugjson = json.loads(body)
                    debugjson_masked = SecurityMasker.mask_simple_body(debugjson)
                    logbody = json.dumps(debugjson_masked)
                headers_masked = SecurityMasker.mask_http_headers(headers)
                LOGGER.debug(
                    "Blobstore REQUEST: %s\n\tPATH: %s\n\tHEADERS: " "%s\n\tBODY: %s",
                    method,
                    str(headers_masked),
                    path,
                    logbody,
                )
            except:
                LOGGER.debug(
                    "Blobstore REQUEST: %s\n\tPATH: %s\n\tHEADERS: " "%s\n\tBODY: %s",
                    method,
                    str(headers),
                    path,
                    "binary body",
                )

        inittime = time.time()

        resp_txt = None
        for idx in range(5):
            try:
                resp_txt = self._conn.rest_immediate(str1)
                break
            except Blob2OverrideError:
                if idx == 4:
                    raise Blob2OverrideError(2)
                continue
            except HpIloChifPacketExchangeError as excp:
                LOGGER.warning("CHIF packet exchange error on attempt %d: %s", idx + 1, str(excp))
                if idx == 4:
                    raise
                try:
                    self._init_connection(**self._connection_properties)
                except Exception as reinit_excp:
                    LOGGER.error("Failed to reinitialize CHIF connection: %s", str(reinit_excp))
                time.sleep(1)
                continue
            except (HpIloError, Exception) as excp:
                LOGGER.warning("Error during rest_immediate on attempt %d: %s", idx + 1, str(excp))
                if idx == 4:
                    raise
                time.sleep(1)
                continue

        endtime = time.time()

        LOGGER.info("iLO Response Time to %s: %s secs.", path, str(endtime - inittime))

        if resp_txt is not None:
            # Dummy response to support a bad host response
            if len(resp_txt) == 0:
                resp_txt = (
                    "HTTP/1.1 500 Not Found\r\nAllow: "
                    "GET\r\nCache-Control: no-cache\r\nContent-length: "
                    "0\r\nContent-type: text/html\r\nDate: Tues, 1 Apr 2025 "
                    "00:00:01 GMT\r\nServer: "
                    "HP-iLO-Server/1.30\r\nX_HP-CHRP-Service-Version: 1.0.3\r\n\r\n\r\n"
                )

            restreq = RestRequest(path, method, data=body, url=self.base_url)
            rest_response = RisRestResponse(restreq, resp_txt)

            if rest_response.status in range(300, 399) and rest_response.status != 304:
                newloc = rest_response.getheader("location")
                newurl = urlparse(newloc)

                rest_response = self.rest_request(newurl.path, method, args, oribody, headers)

            try:
                if rest_response.getheader("content-encoding") == "gzip":
                    if hasattr(gzip, "decompress"):
                        rest_response.read = gzip.decompress(rest_response.ori)
                    else:
                        compressedfile = BytesIO(rest_response.ori)
                        decompressedfile = gzip.GzipFile(fileobj=compressedfile)
                        rest_response.read = decompressedfile.read()
            except Exception:
                pass
            if LOGGER.isEnabledFor(logging.DEBUG):
                headerstr = ""
                headerget = rest_response.getheaders()
                for header in headerget:
                    headerstr += "\t" + header + ": " + headerget[header] + "\n"
                try:
                    response_body = SecurityMasker.mask_complex_body(rest_response.read)

                    LOGGER.debug(
                        "Blobstore RESPONSE for %s:\nCode: %s\nHeaders:" "\n%s\nBody of %s: %s",
                        rest_response.request.path,
                        str(rest_response._http_response.status) + " " + rest_response._http_response.reason,
                        headerstr,
                        rest_response.request.path,
                        response_body,
                    )
                except:
                    LOGGER.debug(
                        "Blobstore RESPONSE for %s:\nCode:%s",
                        rest_response.request.path,
                        rest_response,
                    )
            return rest_response

    def cert_login(self):
        """Login using a certificate."""
        # local cert login is only available on iLO 5
        token = self.cert_login()
        resp = self.rest_request("/redfish/v1/SessionService/Sessions/", "GET")
        if resp.status == 200:
            try:
                location = resp.obj.Oem.Hpe.Links.MySession["@odata.id"]
            except KeyError:
                raise InvalidCertificateError("")
        else:
            raise InvalidCertificateError("")

        return token, location
