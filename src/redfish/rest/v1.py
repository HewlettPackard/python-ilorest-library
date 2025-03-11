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
"""Direct module for working with Redfish/REST technology."""

# ---------Imports---------

import base64
import hashlib
import logging
import sys
from six.moves.urllib.parse import urlparse

from redfish.rest.connections import (
    Blobstore2Connection,
    HttpConnection,
    InvalidCredentialsError,
    OneTimePasscodeError,
    UnauthorizedLoginAttemptError,
    TokenExpiredError,
)

# ---------End of imports---------


# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class ServerDownOrUnreachableError(Exception):
    """Raised when server is unreachable."""

    pass


class JsonDecodingError(Exception):
    """Raised when there is an error in json data."""

    pass


class AuthMethod(object):
    """AUTH Method class

    **BASIC**, **SESSION**, **CERTIFICATE** variables translate to their string counterparts
    `basic`, `session`, `certificate`."""

    BASIC = "basic"
    SESSION = "session"
    CERTIFICATE = "certificate"


class RestClientBase(object):
    """Base REST client. Each RestClientBase has a connection object built by parsing the
    client_kwargs. This connection is used for communicating remotely or locally.

    :param biospassword: The iLO Gen9 bios password. See :func:`bios_password`
    :type biospassword: str
    :param \\**client_kwargs: Arguments to pass to the client argument. For possible values see
                              :mod:`redfish.rest.connections.Blobstore2Connection` for a local
                              connection or :mod:`redfish.rest.connections.HttpConnection`
                              for remote connection."""

    def __init__(self, biospassword=None, **client_kwargs):
        self.connection = None
        self._biospassword = biospassword
        self._build_connection(**client_kwargs)

    @property
    def bios_password(self):
        """Property for the biospassword. Only required on Gen9 iLO 4 when RBSU bios password is set
        and modifying bios settings
        """
        return self._biospassword

    @bios_password.setter
    def bios_password(self, bios_pw):
        """set the bios password"""
        self._biospassword = bios_pw

    def _build_connection(self, **conn_kwargs):
        """Build the appropriate connection for the client"""
        base_url = conn_kwargs.pop("base_url", None)
        if not base_url or base_url.startswith("blobstore://"):
            self.connection = Blobstore2Connection(**conn_kwargs)
        elif not base_url.startswith("https://"):
            base_url = "https://" + base_url
            _ = conn_kwargs.pop("username", None)
            _ = conn_kwargs.pop("password", None)
            _ = conn_kwargs.pop("sessionid", None)
            _ = conn_kwargs.pop("login_otp", None)
            self.connection = HttpConnection(base_url, self._cert_data, **conn_kwargs)
        else:
            _ = conn_kwargs.pop("username", None)
            _ = conn_kwargs.pop("password", None)
            _ = conn_kwargs.pop("sessionid", None)
            _ = conn_kwargs.pop("login_otp", None)
            self.connection = HttpConnection(base_url, self._cert_data, **conn_kwargs)

    def _get_req_headers(self, headers=None):
        """Base _get_req_headers function"""
        return headers if headers else {}

    def get(self, path, args=None, headers=None, noauth=False):
        """Perform a GET request

        :param path: The URI path.
        :type path: str
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        try:
            return self.connection.rest_request(
                path,
                method="GET",
                args=args,
                headers=self._get_req_headers(headers=headers, noauth=noauth),
            )
        except ValueError:
            LOGGER.debug("Error in json object getting path: %s", path)
            raise JsonDecodingError("Error in json decoding.")

    def patch(self, path, body, args=None, headers=None, noauth=False):
        """Perform a PATCH request

        :param path: The URI path.
        :type path: str
        :param body: The body to pass with the request.
        :type body: dict
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        return self.connection.rest_request(
            path,
            body=body,
            method="PATCH",
            args=args,
            headers=self._get_req_headers(headers=headers, noauth=noauth),
        )

    def post(self, path, body, args=None, headers=None, noauth=False):
        """Perform a POST request

        :param path: The URI path.
        :type path: str
        :param body: The body to pass with the request.
        :type body: dict
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        return self.connection.rest_request(
            path,
            body=body,
            method="POST",
            args=args,
            headers=self._get_req_headers(headers=headers, noauth=noauth),
        )

    def put(self, path, body, args=None, headers=None, noauth=False):
        """Perform a PUT request

        :param path: The URI path.
        :type path: str
        :param body: The body to pass with the request.
        :type body: dict
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        return self.connection.rest_request(
            path,
            body=body,
            method="PUT",
            args=args,
            headers=self._get_req_headers(headers=headers, noauth=noauth),
        )

    def head(self, path, headers=None):
        """Perform a HEAD request

        :param path: The URI path.
        :type path: str
        :param headers: Any extra headers to add to the request.
        :type headers: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        return self.connection.rest_request(path, method="HEAD", headers=self._get_req_headers(headers=headers))

    def delete(self, path, headers=None):
        """Perform a DELETE request

        :param path: The URI path.
        :type path: str
        :param args: Any query to add to the URI. (Can also be directly added to the URI)
        :type args: dict
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        return self.connection.rest_request(path, method="DELETE", headers=self._get_req_headers(headers=headers))


class RestClient(RestClientBase):
    """REST client with Redfish and LegacyRest support built on top.

    :param default_prefix: The root of the REST API, either /redfish/v1/ or /rest/v1.
    :type default_prefix: str
    :param is_redfish: Flag to force redfish conformance, even on LegacyRest clients.
    :type is_redfish: bool
    :param username: The username of the account to login with.
    :type username: str
    :param password: The password of the account to login with.
    :type password: str
    :param auth: The authentication type to force.
    :type auth: str or :class:`AuthMethod` class variable.
    :param ca_cert_data: Dictionary containing the certificate authority data (user CA, \
                         user root CA, user root CA key
    :type ca_cert_data: dict
    :param \\**client_kwargs: Arguments to create a :class:`RestClientBase` instance.
    """

    def __init__(
        self,
        default_prefix="/redfish/v1/",
        is_redfish=True,
        username=None,
        password=None,
        sessionid=None,
        base_url=None,
        auth=None,
        ca_cert_data=None,
        login_otp=None,
        session_location=None,
        **client_kwargs
    ):
        """Create a Rest Client object"""
        self.default_prefix = default_prefix
        self.is_redfish = is_redfish
        self.root = None
        self.auth_type = self._get_auth_type(auth, ca_cert_data=ca_cert_data, **client_kwargs)
        self._auth_key = None
        self._user_pass = (username, password)
        self._session_location = None
        self._cert_data = ca_cert_data
        self.login_otp = login_otp
        super(RestClient, self).__init__(
            username=username, password=password, sessionid=sessionid, base_url=base_url, login_otp=login_otp,
            session_location=session_location, **client_kwargs
        )

    def __enter__(self):
        """Create a connection and return the session object"""
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the connection"""
        self.logout()

    def _get_auth_type(self, auth_param, ca_cert_data=None, **client_kwargs):
        """Get the auth type based on key args or positional argument.
        Defaults to session auth."""
        if not auth_param:
            # _ca_cert_data = client_kwargs.get('ca_cert_data')
            if ca_cert_data:
                if ("ca_certs" in ca_cert_data and ca_cert_data["ca_certs"]) or (
                    "cert_file" in ca_cert_data and ca_cert_data["cert_file"]
                ):
                    if (ca_cert_data.get("cert_file") and ca_cert_data.get("key_file")) or ca_cert_data.get("ca_certs"):
                        return AuthMethod.CERTIFICATE
            return AuthMethod.SESSION

        return auth_param

    @property
    def base_url(self):
        """The connection's URL to make calls against"""
        return self.connection.base_url

    @property
    def proxy(self):
        """The connection's proxy, if any."""
        try:
            proxy = self.connection.proxy
        except AttributeError:
            proxy = None
        return proxy

    @property
    def session_key(self):
        """The Client's session key, if any."""
        return self._auth_key if self.auth_type in [AuthMethod.SESSION, AuthMethod.CERTIFICATE] else None

    @session_key.setter
    def session_key(self, ses_key):
        """Set _auth_key to a session key"""
        self._auth_key = ses_key

    @property
    def basic_auth(self):
        """The Client's basic auth header, if any."""
        return self._auth_key if self.auth_type == AuthMethod.BASIC else None

    @basic_auth.setter
    def basic_auth(self, bas_key):
        """Set _auth_key to a basic auth header"""
        self._auth_key = bas_key

    @property
    def session_location(self):
        """The session URI. Used for deleting the session when we logout."""
        session_loc = None
        if self._session_location:
            if self.base_url == "blobstore://.":
                session_loc = self._session_location.replace("https://", "")
                session_loc = session_loc.replace(" ", "%20")
            else:
                parse_object = urlparse(self.base_url)
                if parse_object.hostname is not None:
                    newurl = "https://" + parse_object.hostname
                    session_loc = self._session_location.replace(newurl, "")
                else:
                    session_loc = self._session_location.replace(self.base_url, "")
        return session_loc

    @session_location.setter
    def session_location(self, ses_loc):
        """Set the session URI"""
        login_url_p = urlparse(self.base_url)
        new_port = login_url_p.port
        # The session_url returned by iLO does not include the port information
        # If we're using a non-standard port to connect to iLO we have to
        # manually insert it, based on the base_url.
        if new_port and ses_loc:
            session_location_p = urlparse(ses_loc)
            session_location_p = session_location_p._replace(
                netloc="{}:{}".format(session_location_p.hostname, new_port)
            )
            self._session_location = session_location_p.geturl()
        else:
            self._session_location = ses_loc

    @property
    def username(self):
        """The username, if any. Once a login function has been called the credentials are removed
        from memory for security and this will return None."""
        return self._user_pass[0]

    @property
    def password(self):
        """The password, if any. Once a login function has been called the credentials are removed
        from memory for security and this will return None."""
        return self._user_pass[1]

    @property
    def login_url(self):
        """The login URI from the root response. This is where we post the
        credentials for a login."""
        login_url = None

        try:
            login_url = self.root.obj.Links.Sessions["@odata.id"]
        except KeyError:
            login_url = self.root.obj.links.Sessions.href
        finally:
            if not login_url:
                raise ServerDownOrUnreachableError("Cannot locate the login url. Is this a Rest or" " Redfish server?")
        return login_url

    def login(self, auth=AuthMethod.SESSION):
        """Login to a Redfish or LegacyRest server.
        If auth is not supplied login will intelligently
        choose the authentication mode based on the arguments passed.
        Basic authentication MUST be specified with `auth`.

        :param auth: The auth type to login with.
        :type auth: str or :class:`AuthMethod` class variable
        """
        if auth:
            auth = self._get_auth_type(auth)
            self.auth_type = auth

        if self.auth_type is AuthMethod.BASIC:
            self._get_root()
            self._basic_login()
        elif self.auth_type is AuthMethod.SESSION:
            self._get_root()
            self._session_login()
        elif self.auth_type is AuthMethod.CERTIFICATE:
            self._cert_login()
            self._get_root()

    def logout(self):
        """Logout of session.

        YOU MUST CALL THIS WHEN YOU ARE DONE TO FREE UP SESSIONS"""
        if self.session_location:
            resp = self.delete(self.session_location)
            LOGGER.info("User logged out: %s", resp.read)
        self._auth_key = None
        self.session_location = None

    def _get_root(self):
        """Get the root response of the server"""
        if not self.root:
            resp = self.get(self.default_prefix)

            if resp.status != 200:
                raise ServerDownOrUnreachableError("Server not reachable, " "return code: %d" % resp.status)
            self.root = resp

    def _basic_login(self):
        """Login using basic authentication"""
        LOGGER.info("Performing basic authentication.")
        if not self.basic_auth:
            auth_key = base64.b64encode(("{}:{}".format(self.username, self.password)).encode("utf-8")).decode("utf-8")
            self.basic_auth = "Basic {}".format(auth_key)

        headers = dict()
        headers["Authorization"] = self.basic_auth

        respvalidate = self.get(self.login_url, headers=headers)

        if respvalidate.status == 401:
            self._credential_err()
        else:
            self._user_pass = (None, None)

    def _session_login(self):
        """Login using session authentication"""
        if not self.connection.session_key:
            LOGGER.info("Performing session authentication.")
            data = dict()
            data["UserName"] = self.username
            data["Password"] = self.password
            if self.login_otp is not None:
                data["Token"] = self.login_otp

            headers = dict()
            resp = self.post(self.login_url, body=data, headers=headers)
            try:
                respread = resp.read
                respread = respread.replace("\\\\", "\\")
                # LOGGER.info("%s" % respread)
            except ValueError:
                pass
            LOGGER.debug("Login returned code %s: %s", resp.status, respread)

            self.session_key = resp.session_key
            self.session_location = resp.session_location
            self.login_return_code = resp.status
            self.login_response = respread
        else:
            self.session_key = self.connection.session_key
            if self.connection.session_location:
                self.session_location = self.connection.session_location

        if hasattr(self, "login_response") and self.login_response:
            if "OneTimePasscodeSent" in self.login_response:
                raise OneTimePasscodeError()
            elif "UnauthorizedLogin" in self.login_response:
                if self.login_otp:
                    raise UnauthorizedLoginAttemptError("Error " + str(
                        self.login_return_code) + ". Login is unauthorized.\n"
                                                  "Please check the credentials/OTP entered.\n")
                else:
                    self._credential_err()
            elif "TokenExpired" in self.login_response:
                raise TokenExpiredError("Error " + str(
                    self.login_return_code) + ". The OTP entered has expired. Please enter credentials again.\n")
        elif not self.session_key and not resp.status == 200:
            self._credential_err()
        else:
            self._user_pass = (None, None)

    def _cert_login(self):
        """Login using certificate authentication"""
        self.session_key, self.session_location = self.connection.cert_login()

    def _credential_err(self):
        """Return credential error based on delay"""
        try:
            if self.is_redfish:
                delay = self.root.obj.Oem.Hpe.Sessions.LoginFailureDelay
            else:
                delay = self.root.obj.Oem.Hp.Sessions.LoginFailureDelay
        except KeyError:
            delay = 5

        raise InvalidCredentialsError(delay)

    def _get_req_headers(self, headers=None, optionalpassword=None, noauth=False):
        """Get the request headers

        :param headers: additional headers to be utilized
        :type headers: str
        :param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
        :returns: returns headers
        """
        headers = headers if isinstance(headers, dict) else dict()
        h_list = [header.lower() for header in headers]

        auth_headers = True if "x-auth-token" in h_list or "authorization" in h_list else False

        token = self._biospassword if self._biospassword else optionalpassword
        if token:
            token = optionalpassword.encode("utf-8") if type(optionalpassword).__name__ in "basestr" else token
            hash_object = hashlib.new("SHA256")
            hash_object.update(token)
            if not noauth:
                headers["X-HPRESTFULAPI-AuthToken"] = hash_object.hexdigest().upper()

        if self.session_key and not auth_headers:
            if not noauth:
                headers["X-Auth-Token"] = self.session_key
        elif self.basic_auth and not auth_headers:
            if not noauth:
                headers["Authorization"] = self.basic_auth

        if self.is_redfish:
            if not noauth:
                headers["OData-Version"] = "4.0"

        return headers

    def get_resource_directory(self):
        try:
            resource_uri = self.root.obj.Oem.Hpe.Links.ResourceDirectory["@odata.id"]
        except KeyError:
            sys.stderr.write("Resource directory is only available on HPE servers.\n")
            return None

        response = self.get(resource_uri)
        resources = []

        if response.status == 200:
            sys.stdout.write("\tFound resource directory at /redfish/v1/resourcedirectory" + "\n\n")
            resources = response.dict["Instances"]
        else:
            sys.stderr.write("\tResource directory missing at /redfish/v1/resourcedirectory" + "\n")

        return resources

    def get_gen(self):
        rootresp = self.root.obj
        # Default iLO 5
        ilogen = 5
        iloversion = None
        gencompany = next(iter(rootresp.get("Oem", {}).keys()), None) in ("Hpe", "Hp")
        comp = "Hp" if gencompany else None
        comp = "Hpe" if rootresp.get("Oem", {}).get("Hpe", None) else comp
        if comp and next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerType", None):
            ilogen = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerType")
            ilover = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerFirmwareVersion")
            if ilogen.split(" ")[-1] == "CM":
                # Assume iLO 4 types in Moonshot
                ilogen = 4
                iloversion = None
            else:
                ilogen = ilogen.split(" ")[1]
                iloversion = float(ilogen.split(" ")[-1] + "." + "".join(ilover.split(".")))
        return (ilogen, iloversion)


class LegacyRestClient(RestClient):
    """Class for a **Legacy REST** client instance.
    Instantiates appropriate Rest object based on existing configuration.
    Use this to retrieve a pre-configured Legacy Rest Class.

    Basic arguments include (These can be omitted for most local connections):

    * **base_url**: The IP or Hostname of the server to perform operations on.
    * **username**: The username of the account to login with.
    * **password**: The username of the account to login with.

    For full description of the arguments allowed see :class:`RestClient`"""

    def __init__(self, **client_kwargs):
        kwargs = {
            "default_prefix": client_kwargs.pop("default_prefix", "/rest/v1"),
            "is_redfish": client_kwargs.pop("is_redfish", False),
        }
        kwargs.update(client_kwargs)
        super(LegacyRestClient, self).__init__(**kwargs)


class RedfishClient(RestClient):
    """Class for a **Redfish** client instance.
    Instantiates appropriate Redfish object based on existing configuration.
    Use this to retrieve a pre-configured Redfish Class.

    Basic arguments include (These can be omitted for most local connections):

    * **base_url**: The IP or Hostname of the server to perform operations on. None for local.
    * **username**: The username of the account to login with.
    * **password**: The username of the account to login with.

    For full description of the arguments allowed see :class:`RestClient`"""

    def __init__(self, **client_kwargs):
        kwargs = {
            "default_prefix": client_kwargs.pop("default_prefix", "/redfish/v1"),
            "is_redfish": client_kwargs.pop("is_redfish", True),
        }
        kwargs.update(client_kwargs)
        super(RedfishClient, self).__init__(**kwargs)
