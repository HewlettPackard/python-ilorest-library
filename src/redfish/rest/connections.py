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
)
from redfish.hpilo.rishpilo import HpIloChifPacketExchangeError
from redfish.rest.containers import RestRequest, RestResponse, RisRestResponse

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
            'timeout': urllib3.util.Timeout(connect=4800, read=4800),
            'retries': urllib3.util.Retry(connect=50, read=50, redirect=50),
        }
        self._connection_properties.update(client_kwargs)
        if cert_data:
            if ("cert_file" in cert_data and cert_data["cert_file"]) or (
                "ca_certs" in cert_data and cert_data["ca_certs"]
            ):
                self._connection_properties.update({"ca_cert_data": cert_data})
        self._proxy = self._connection_properties.pop("proxy", None)
        self.session_key = self._connection_properties.pop("session_key", None)
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
        cert_reqs = "CERT_NONE"
        if self._connection_properties.get("ca_cert_data"):
            LOGGER.info("Using CA cert to confirm identity.")
            cert_reqs = "CERT_NONE"
            self._connection_properties.update(self._connection_properties.pop("ca_cert_data"))

        if self.proxy:
            if self.proxy.startswith("socks"):
                LOGGER.info("Initializing a SOCKS proxy.")
                http = SOCKSProxyManager(
                    self.proxy,
                    cert_reqs=cert_reqs,
                    maxsize=50,
                    **self._connection_properties
                )
            else:
                LOGGER.info("Initializing a HTTP proxy.")
                http = ProxyManager(
                    self.proxy,
                    cert_reqs=cert_reqs,
                    maxsize=50,
                    **self._connection_properties
                )
        else:
            LOGGER.info("Initializing no proxy.")
            try:
                self._connection_properties.pop("ca_cert_data")
            except KeyError:
                pass

            http = PoolManager(
                cert_reqs=cert_reqs,
                maxsize=50,
                **self._connection_properties
            )

        self._conn = http.request

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
                    if "Password" in debugjson.keys():
                        debugjson["Password"] = "******"
                    if "OldPassword" in debugjson.keys():
                        debugjson["OldPassword"] = "******"
                    if "NewPassword" in debugjson.keys():
                        debugjson["NewPassword"] = "******"
                    logbody = json.dumps(debugjson)
                    logbody = logbody.replace("\\\\", "\\")
                LOGGER.debug(
                    "HTTP REQUEST: %s\n\tPATH: %s\n\t" "HEADERS: %s\n\tBODY: %s",
                    restreq.method,
                    restreq.path,
                    headers,
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
        except MaxRetryError:
            vnic_url = "16.1.15.1"
            if reqfullpath.find(vnic_url) != -1:
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
                    LOGGER.debug(
                        "HTTP RESPONSE for %s:\nCode:%s\nHeaders:" "\n%s\nBody Response of %s: %s",
                        restresp.request.path,
                        str(restresp._http_response.status) + " " + restresp._http_response.reason,
                        headerstr,
                        restresp.request.path,
                        restresp.read,
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
        self._connection_properties = conn_kwargs
        self.session_key = self._connection_properties.pop("sessionid", None)
        self._init_connection(**self._connection_properties)

    def _init_connection(self, **kwargs):
        """Initiate blobstore connection"""
        # mixed security modes require a password at all times
        username = kwargs.pop("username", "nousername")
        if isinstance(username, bytes):
            username = username.decode("utf-8")
        password = kwargs.pop("password", "nopassword")
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        log_dir = kwargs.pop("log_dir", "")
        try:
            correctcreds = BlobStore2.initializecreds(username=username, password=password, log_dir=log_dir)
            bs2 = BlobStore2(log_dir=log_dir)
            if not correctcreds:
                security_state = int(bs2.get_security_state())
                if security_state == 3:
                    raise InvalidCredentialsError(0)
                else:
                    raise SecurityStateError(security_state)
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
                str1 = bytearray(str1.encode("ASCII")) + body
            else:
                str1 += body

        if not isinstance(str1, bytearray):
            str1 = bytearray(str1.encode("ASCII"))

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
                    if "Password" in debugjson.keys():
                        debugjson["Password"] = "******"
                    if "OldPassword" in debugjson.keys():
                        debugjson["OldPassword"] = "******"
                    if "NewPassword" in debugjson.keys():
                        debugjson["NewPassword"] = "******"
                    logbody = json.dumps(debugjson)

                LOGGER.debug(
                    "Blobstore REQUEST: %s\n\tPATH: %s\n\tHEADERS: " "%s\n\tBODY: %s",
                    method,
                    str(headers),
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

        for idx in range(5):
            try:
                resp_txt = self._conn.rest_immediate(str1)
                break
            except Blob2OverrideError:
                if idx == 4:
                    raise Blob2OverrideError(2)
                else:
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
                    LOGGER.debug(
                        "Blobstore RESPONSE for %s:\nCode: %s\nHeaders:" "\n%s\nBody of %s: %s",
                        rest_response.request.path,
                        str(rest_response._http_response.status) + " " + rest_response._http_response.reason,
                        headerstr,
                        rest_response.request.path,
                        rest_response.read,
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
