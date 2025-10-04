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
"""RMC helper file. Includes RMC errors and caching functionality for monolith."""

# ---------Imports---------

import errno
import hashlib
import json
import logging
import os

from redfish.rest.containers import RestRequest, StaticRestResponse
from redfish.rest.v1 import RestClient

from .ris import RisMonolith
from .sharedtypes import JSONEncoder

# ---------End of imports---------

# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class RdmcError(Exception):
    """Base class for all RDMC Exceptions"""

    errcode = 1

    def __init__(self, message):
        Exception.__init__(self, message)


class InvalidCommandLineError(RdmcError):
    """Raised when user enter incorrect command line arguments"""

    pass

class TfaEnablePreRequisiteError(RdmcError):
    """Raised when pre-requisites not met while enabling TFA"""

    pass

class FailureDuringCommitError(RdmcError):
    """Raised when there is an error while committing."""

    pass


class UserNotAdminError(RdmcError):
    """Raised when user doesn't have admin priviledges, but they are required."""

    pass


class IncompatibleiLOVersionError(RdmcError):
    """Raised when iLO version is incompatible."""

    pass


class UndefinedClientError(Exception):
    """Raised when there are no clients active (usually when user hasn't logged in)."""

    pass


class InstanceNotFoundError(Exception):
    """Raised when attempting to select an instance that does not exist."""

    pass


class CurrentlyLoggedInError(Exception):
    """Raised when attempting to select an instance that does not exist"""

    pass


class IloLicenseError(Exception):
    """Raised when the proper iLO license is not available for a command"""

    pass


class ScepenabledError(Exception):
    """Raised when the generation csr or deletion of https cert is issues when scep is enabled"""

    pass


class NothingSelectedError(Exception):
    """Raised when attempting to access an object without first selecting it."""

    pass


class NothingSelectedFilterError(Exception):
    """Raised when the filter applied doesn't match any selection (general)."""

    pass


class NothingSelectedSetError(Exception):
    """Raised when attempting to access an object without first selecting it (In set)."""

    pass


class InvalidSelectionError(Exception):
    """Raised when selection argument fails to match anything."""

    pass


class IdTokenError(Exception):
    """Raised when user is not authorized to complete the operation."""

    pass


class ValueChangedError(Exception):
    """Raised if user tries to set/commit a value when monolith has older data."""

    pass


class LoadSkipSettingError(Exception):
    """Raised when one or more settings are absent in given server."""

    pass


class InvalidPathError(Exception):
    """Raised when requested path is not found."""

    pass


class UnableToObtainIloVersionError(Exception):
    """Raised when iloversion is missing from default path."""

    pass


class ValidationError(Exception):
    """Raised when there is a problem with user input."""

    def __init__(self, errlist):
        super(ValidationError, self).__init__(errlist)
        self._errlist = errlist

    def get_errors(self):
        """Returns error list."""
        return self._errlist


class IloResponseError(Exception):
    """Raised when iLO returns with a non 2XX response."""

    pass


class EmptyRaiseForEAFP(Exception):
    """Raised when you need to check for issues and take different action."""

    pass


class IncorrectPropValue(Exception):
    """Raised when you pass an incorrect value to for the associated property."""

    pass


class RmcCacheManager(object):
    """Manages caching/uncaching of data for RmcApp.

    :param rmc: RmcApp to be managed
    :type rmc: :class:`redfish.ris.rmc.RmcApp`
    """

    def __init__(self, rmc):
        """Initialize RmcCacheManager

        :param rmc: RmcApp to be managed
        :type rmc: RmcApp object

        """
        self._rmc = rmc

        self.encodefunct = lambda data: data
        self.decodefunct = lambda data: data


class RmcFileCacheManager(RmcCacheManager):
    """RMC file cache manager.

    :param rmc: RmcApp to be managed
    :type rmc: :class:`redfish.ris.rmc.RmcApp`
    """

    def __init__(self, rmc):
        super(RmcFileCacheManager, self).__init__(rmc)

    def logout_del_function(self, url=None):
        """Searches for a specific url in cache or returns all urls and returns them for RmcApp
        to run logout on, clearing the session.

        :param url: The URL to pass back for logout.
        :type url: str
        """
        if self._rmc.cache:
            cachedir = self._rmc.cachedir
            indexfn = os.path.join(cachedir, "index")  # %s\\index' % cachedir
        else:
            indexfn = ""
        sessionlocs = []

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, "r")
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    if url:
                        if url in index["url"]:
                            os.remove(os.path.join(cachedir, index["href"]))
                            break
                    else:
                        if os.path.isfile(os.path.join(cachedir, index["href"])):
                            monolith = open(os.path.join(cachedir, index["href"]), "r")
                            data = json.load(monolith)
                            monolith.close()
                            for item in data:
                                if "login" in item and "session_location" in data["login"]:
                                    if "blobstore" in data["login"]["url"]:
                                        loc = data["login"]["session_location"].split("//")[-1]
                                        sesurl = None
                                    else:
                                        loc = None
                                        if data["login"]["session_location"] is not None:
                                            loc = data["login"]["session_location"].split(data["login"]["url"])[-1]
                                        sesurl = data["login"]["url"]
                                    sessionlocs.append(
                                        (
                                            loc,
                                            sesurl,
                                            self._rmc._cm.decodefunct(data["login"]["session_key"]),
                                        )
                                    )

                        os.remove(os.path.join(cachedir, index["href"]))
            except BaseException as excp:
                LOGGER.warning("Unable to read cache data %s", excp)

        return sessionlocs

    def uncache_rmc(self, creds=None, enc=False):
        """Uncaches monolith data from cache location specified by RmcApp.

        :param creds: Dictionary of username and password.
                      Only required for restoring high security local calls.
        :type creds: dict
        :param enc: Flag if credentials passed are encoded.
        :type enc: bool
        """
        cachedir = self._rmc.cachedir
        indexfn = "%s/index" % cachedir

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, "r")
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    clientfn = index["href"]
                    self._uncache_client(clientfn, creds=creds, enc=enc)
            except BaseException as excp:
                LOGGER.warning("Unable to read cache data %s", excp)

    def _uncache_client(self, cachefn, creds=None, enc=False):
        """Monolith uncache function for parsing and passing all client data and associated
           credential attributes.

        :param cachefn: The cache file name.
        :type cachefn: str.

        """
        cachedir = self._rmc.cachedir
        clientsfn = "%s/%s" % (cachedir, cachefn)

        if os.path.isfile(clientsfn):
            try:
                clientsfh = open(clientsfn, "r")
                client = json.load(clientsfh)
                clientsfh.close()

                if "login" not in client:
                    return

                login_data = client["login"]
                if "url" not in login_data:
                    return

                self._rmc.typepath.getgen(
                    login_data.get("ilo"),
                    url=login_data.get("url"),
                    isredfish=login_data.get("redfish", None),
                    ca_cert_data=login_data.get("ca_cert_data", {}),
                )

                if creds and login_data.get("url", "").startswith("blobstore://"):
                    if enc:
                        creds["username"] = self._rmc._cm.decodefunct(creds["username"])
                        creds["password"] = self._rmc._cm.decodefunct(creds["password"])
                    login_data["username"] = creds["username"]
                    login_data["password"] = creds["password"]
                    if isinstance(login_data["username"], bytes):
                        login_data["username"] = login_data["username"].decode("utf-8")
                    if isinstance(login_data["password"], bytes):
                        login_data["password"] = login_data["password"].decode("utf-8")

                redfishinst = RestClient(
                    username=login_data.get("username", "Administrator"),
                    password=login_data.get("password", None),
                    base_url=login_data.get("url", None),
                    biospassword=login_data.get("bios_password", None),
                    is_redfish=login_data.get("redfish", None),
                    default_prefix=self._rmc.typepath.defs.startpath,
                    proxy=login_data.get("proxy", None),
                    ca_cert_data=login_data.get("ca_cert_data", {}),
                )
                if login_data.get("authorization_key"):
                    redfishinst.basic_auth = login_data.get("authorization_key")
                elif login_data.get("session_key"):
                    redfishinst.session_key = self._rmc._cm.decodefunct(login_data.get("session_key"))
                    if isinstance(redfishinst.session_key, bytes):
                        redfishinst.session_key = redfishinst.session_key.decode("utf-8")
                    redfishinst.session_location = login_data.get("session_location")

                if "selector" in client:
                    self._rmc.selector = client["selector"]
                if login_data.get("iloversion"):
                    redfishinst.iloversion = login_data.get("iloversion")
                else:
                    redfishinst.iloversion = None
                self._rmc.typepath.iloversion = redfishinst.iloversion

                getdata = client["get"]
                for key in list(getdata.keys()):
                    if key == redfishinst.default_prefix:
                        restreq = RestRequest(method="GET", path=key)
                        getdata[key]["restreq"] = restreq
                        redfishinst.root = StaticRestResponse(**getdata[key])
                        break

                self._rmc.monolith = RisMonolith(redfishinst, self._rmc.typepath)
                self._rmc.monolith.load_from_dict(client["monolith"])
                self._rmc.redfishinst = redfishinst
                # make sure root is there
                _ = redfishinst.root
                self._rmc.typepath.defineregschemapath(redfishinst.root.dict)
            except BaseException as excp:
                LOGGER.warning("Unable to read cache data %s", excp)

    def cache_rmc(self):
        """Saves monolith data to the file path specified in RmcApp."""
        if not self._rmc.cache:
            return

        cachedir = self._rmc.cachedir
        if not os.path.isdir(cachedir):
            try:
                os.makedirs(cachedir)
            except OSError as ex:
                if ex.errno == errno.EEXIST:
                    pass
                else:
                    raise

        index_map = dict()
        index_cache = list()

        if self._rmc.redfishinst:
            shaobj = hashlib.new("SHA256")
            shaobj.update(self._rmc.redfishinst.base_url.encode("utf-8"))
            md5str = shaobj.hexdigest()

            index_map[self._rmc.redfishinst.base_url] = md5str
            index_data = dict(
                url=self._rmc.redfishinst.base_url,
                href="%s" % md5str,
            )
            index_cache.append(index_data)

            indexfh = open("%s/index" % cachedir, "w")
            json.dump(index_cache, indexfh, indent=2, cls=JSONEncoder)
            indexfh.close()

        if self._rmc.redfishinst:
            login_data = dict(
                username=None,
                password=None,
                url=self._rmc.redfishinst.base_url,
                session_key=self._rmc._cm.encodefunct(self._rmc.redfishinst.session_key),
                session_location=self._rmc.redfishinst.session_location,
                authorization_key=self._rmc.redfishinst.basic_auth,
                bios_password=self._rmc.redfishinst.bios_password,
                redfish=self._rmc.monolith.is_redfish,
                ilo=self._rmc.typepath.ilogen,
                iloversion=self._rmc.typepath.iloversion,
                proxy=self._rmc.redfishinst.proxy,
                ca_cert_data=self._rmc.redfishinst.connection._connection_properties
                if self._rmc.redfishinst.connection._connection_properties
                else dict(),
            )

            clients_data = dict(
                selector=self._rmc.selector,
                login=login_data,
                monolith=self._rmc.monolith,
                get=self._rmc.monolith.paths,
            )

            clientsfh = open("%s/%s" % (cachedir, index_map[self._rmc.redfishinst.base_url]), "w")

            if isinstance(clients_data, bytes):
                clients_data = clients_data.decode("utf-8")
            json.dump(clients_data, clientsfh, indent=2, cls=JSONEncoder)
            clientsfh.close()
