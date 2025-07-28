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
"""Monolith database implementation. Crawls Redfish and Legacy REST implementations
and holds all data retrieved. The created database is called the **monolith** and referenced as
such in the code documentation."""

# ---------Imports---------

import logging
import re
import sys
import threading
from re import error as regexerr

# Added for py3 compatibility
import six

try:
    from collections import OrderedDict, defaultdict
except ImportError:
    from collections.abc import OrderedDict, defaultdict

from queue import Queue

import jsonpath_rw
import jsonpointer
from jsonpointer import set_pointer
from six.moves.urllib.parse import urlparse, urlunparse
from six.moves.urllib.parse import ParseResult
from six.moves.urllib.parse import quote

from redfish.rest.containers import RestRequest, StaticRestResponse
from redfish.ris.ris_threaded import LoadWorker
from redfish.ris.sharedtypes import Dictable

# ---------End of imports---------

# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class BiosUnregisteredError(Exception):
    """Raised when BIOS has not been registered correctly in iLO"""

    pass


class SchemaValidationError(Exception):
    """Schema Validation Class Error"""

    pass


class SessionExpired(Exception):
    """Raised when session has expired"""

    pass


class RisMonolithMemberBase(Dictable):
    """RIS monolith member base class"""

    pass


class RisInstanceNotFoundError(Exception):
    """Raised when attempting to select an instance that does not exist"""

    pass


class RisMonolithMemberv100(RisMonolithMemberBase):
    """Class used by :class:`RisMonolith` for holding information on a response and adds extra data
    for monolith usage. A member can be marked as *modified* which means another operation may have
    rendered this member out of date. It should be reloaded before continuing to ensure data is
    up to date.

    :param restresp: `RestResponse` to create a member from.
    :type restresp: :class:`redfish.rest.containers.RestResponse`
    :param isredfish: Flag if the response is redfish or not
    :type isredfish: bool
    """

    def __init__(self, restresp=None, isredfish=True):
        self._resp = restresp
        self._patches = list()
        # Check if typedef can be used here
        self._typestring = "@odata.type" if isredfish else "Type"
        self.modified = False
        self.defpath = self.deftype = self.defetag = self._type = None
        self.__bool__ = self.__nonzero__

    @property
    def type(self):
        """Get type of the monolith member's response"""
        try:
            if self and self._typestring in self.resp.dict:
                return self.resp.dict[self._typestring]
            # Added for object type
            elif self and "type" in self.resp.dict:
                return self.resp.dict["type"]
        except (AttributeError, ValueError, TypeError):
            return self.deftype  # data not yet fetched, probably empty dict, so assume deftype
        return None

    @property
    def maj_type(self):
        """Get major type of the monolith member's response"""
        if self.type:
            if "." in self.type:
                types = ".".join(self.type.split(".", 2)[:2])
                retval = types[1:] if types.startswith("#") else types
            else:
                retval = self.type
            return retval
        return self.deftype

    def __nonzero__(self):
        """Defining the bool value for the class"""
        return True if self.resp else False

    @property
    def resp(self):
        """Get the entire response of the monolith member"""
        return self._resp

    @property
    def path(self):
        """Get path of the monolith member's response"""

        try:
            if self:
                return self.resp.request.path
        except (AttributeError, ValueError):
            pass
        return self.defpath

    @property
    def patches(self):
        """Get patches for the monolith member"""
        return self._patches

    @patches.setter
    def patches(self, val):
        """Set patches for the monolith member"""
        self._patches = val

    @property
    def dict(self):
        """Get the dictionary of the monolith member's response"""
        return self._resp.dict

    @property
    def etag(self):
        """Get the etag of the response"""
        return self.defetag if not self.resp else self.resp.getheader("etag")

    def popdefs(self, typename, pathval, etagval):
        """Populate the default values in the class

        :param typename: The default **Type** string. Example: @odata.type
        :type typename: str
        :param pathval: The default **Path** string. Example: @odata.id
        :type pathval: str
        :param etagval: The default **ETag** value.
        :type etagval: str
        """
        self.defetag = etagval
        self.deftype = typename
        self.defpath = pathval

    def to_dict(self):
        """Converts Monolith Member to a dictionary. This is the reverse of :func:`load_from_dict`.

        :returns: returns the Monolith Member in dictionary form
        """
        result = OrderedDict()
        if self.maj_type:
            result["Type"] = self.type

            if self.resp:
                if self.maj_type == "Collection.1" and "MemberType" in self.resp.dict:
                    result["MemberType"] = self.resp.dict["MemberType"]

            result["links"] = OrderedDict()
            result["links"]["href"] = ""
            result["ETag"] = self.etag

            if self.resp:
                result["Content"] = self.resp.dict
                result["Status"] = self.resp.status
                result["Headers"] = self.resp.getheaders()
            result["OriginalUri"] = self.path
            result["Patches"] = self._patches
            result["modified"] = self.modified
            result["MajType"] = self.maj_type

        return result

    def load_from_dict(self, src):
        """Load variables to a monolith member from a dictionary.
        This is the reverse of :func:`to_dict`.

        :param src: Source to load member data from.
        :type src: dict
        """
        if "Type" in src:
            self._type = src["Type"]
            if "Content" in src:
                restreq = RestRequest(method="GET", path=src["OriginalUri"])
                src["restreq"] = restreq
                self._resp = StaticRestResponse(**src)
            self.deftype = src["MajType"]
            self.defpath = src["OriginalUri"]
            self.defetag = src["ETag"]
            self._patches = src["Patches"]
            self.modified = src["modified"]


class RisMonolith(Dictable):
    """Monolithic cache of RIS data. This takes a :class:`redfish.rest.v1.RestClient` and uses it to
    gather data from a server and saves it in a modifiable database called monolith.

    :param client: client to use for data retrieval.
    :type client: :class:`redfish.rest.v1.RestClient`
    :param typepath: The compatibility class to use for differentiating between Redfish/LegacyRest.
    :type typepath: :class:`redfish.rest.ris.Typesandpathdefines`
    :param directory_load: The flag to quick load using resource directory if possible.
           When set to True this will load paths, etags, and types, but not create responses for
           every monolith member. When responses are needed, they will need to be loaded separately.
    :type directory_load: bool
    """

    def __init__(self, client, typepath, directory_load=True):
        self._client = client
        self.name = "Monolithic output of RIS Service"
        self._visited_urls = list()
        self._type = None
        self._name = None
        self.progress = 0
        self._directory_load = directory_load
        self.is_redfish = self.client.is_redfish
        self.typesadded = defaultdict(set)
        self.paths = dict()
        self.ctree = defaultdict(set)
        self.colltypes = defaultdict(set)

        self.typepath = typepath
        self.collstr = self.typepath.defs.collectionstring
        self.etagstr = "ETag"
        if self.is_redfish:
            self._resourcedir = "/redfish/v1/ResourceDirectory/"
        else:
            self._resourcedir = "/rest/v1/ResourceDirectory"

        # MultiThreading
        self.get_queue = Queue()
        self.threads = []

    @property
    def directory_load(self):
        """The flag to gather information about a tree without downloading every path. Only usable
        on HPE systems with a ResourceDirectory. type"""
        return self._directory_load

    @directory_load.setter
    def directory_load(self, dir_load):
        """Set the directory_load flag"""
        self._directory_load = dir_load

    @property
    def type(self):
        """Return monolith version type"""
        return "Monolith.1.0.0"

    @property
    def visited_urls(self):
        """The urls visited by the monolith"""
        return list(set(self._visited_urls) | set(self.paths.keys()))

    @visited_urls.setter
    def visited_urls(self, visited_urls):
        """Set visited URLS."""
        self._visited_urls = visited_urls

    @property
    def types(self):
        """Returns list of types for members in the monolith

        :rtype: list
        """
        return list(self.typesadded.keys())

    @types.setter
    def types(self, member):
        """Adds a member to monolith

        :param member: Member created based on response.
        :type member: RisMonolithMemberv100
        """
        self.typesadded[member.maj_type].add(member.path)
        patches = []
        if member.path in list(self.paths.keys()):
            patches = self.paths[member.path].patches
        self.paths[member.path] = member
        self.paths[member.path].patches.extend([patch for patch in patches])

    @property
    def client(self):
        """Returns the current client object reference

        :rtype: class object
        """
        return self._client

    @client.setter
    def client(self, curr_client):
        """Set the current client

        :param curr_client: current client object
        :type curr_client: class object
        """
        self._client = curr_client

    def path(self, path):
        """Provides the member corresponding to the path specified. Case sensitive.

        :param path: path of the monolith member to return
        :type path: str
        :rtype: RisMonolithMemberv100
        """
        try:
            return self.paths[path]
        except:
            return None

    def iter(self, typeval=None):
        """An iterator that yields each member of monolith associated with a specific type. In the
        case that no type is included this will yield all members in the monolith.

        :rtype: RisMonolithMemberv100
        """
        if not typeval:
            for _, val in list(self.paths.items()):
                yield val
        else:
            for typename in self.gettypename(typeval):
                for item in self.typesadded[typename]:
                    yield self.paths[item]

    #             types = next(self.gettypename(typeval), None)
    #             if types in self.typesadded:
    #                 for item in self.typesadded[types]:
    #                     yield self.paths[item]
    #             else:
    #                 raise RisInstanceNotFoundError("Unable to locate instance for" \
    #                                                             " '%s'\n" % typeval)

    def itertype(self, typeval):
        """Iterator that yields member(s) of given type in the monolith and raises an error if no
        member of that type is found.

        :param typeval: type name of the requested member.
        :type typeval: str
        :rtype: RisMonolithMemberv100
        """
        typeiter = self.gettypename(typeval)
        types = next(typeiter, None)
        if types:
            while types:
                for item in self.typesadded[types]:
                    yield self.paths[item]
                types = next(typeiter, None)
        else:
            raise RisInstanceNotFoundError("Unable to locate instance for '%s'\n" % typeval)

    def typecheck(self, types):
        """Check if a member of given type exists in the monolith

        :param types: type to check.
        :type types: str
        :rtype: bool
        """
        if any(types in val for val in self.types):
            return True
        return False

    def gettypename(self, types):
        """Takes a full type response and returns all major types associated.
        Example: #Type.v1_0_0.Type will return iter(Type.1)

        :param types: The type of the requested response.
        :type types: str
        :rtype: iter of major types
        """
        types = types[1:] if types[0] in ("#", "#") else types
        return iter((xt for xt in self.types if xt and types.lower() in xt.lower()))

    def update_member(self, member=None, resp=None, path=None, init=True):
        """Adds member to the monolith. If the member already exists the
        data is updated in place. Takes either a RisMonolithMemberv100 instance or a
        :class:`redfish.rest.containers.RestResponse` along with that responses path.

        :param member: The monolith member to add to the monolith.
        :type member: RisMonolithMemberv100
        :param resp: The rest response to add to the monolith.
        :type resp: :class:`redfish.rest.containers.RestResponse`
        :param path: The path correlating to the response.
        :type path: str
        :param init: Flag if addition is part of the initial load. Set this to false if you are
                     calling this by itself.
        :type init: bool
        """
        if not member and resp and path:
            self._visited_urls.append(path.lower())

            member = RisMonolithMemberv100(resp, self.is_redfish)
            if not member:  # Assuming for lack of member and not member.type
                return
            if not member.type:
                member.deftype = "object"  # Hack for general schema with no type

        self.types = member

        if init:
            self.progress += 1
            if LOGGER.getEffectiveLevel() == 40:
                self._update_progress()

    def load(
        self,
        path=None,
        includelogs=False,
        init=False,
        crawl=True,
        loadtype="href",
        loadcomplete=False,
        path_refresh=False,
        json_out=False,
        single=True,
    ):
        """Walks the entire data model and caches all responses or loads an individual path into
        the monolith. Supports both threaded and sequential crawling.

        :param path: The path to start the crawl from the provided path if crawling or
                     loads the path into monolith. If path is not included, crawl will start with
                     the default. The default is */redfish/v1/* or */rest/v1* depending on if the
                     system is Redfish or LegacyRest.
        :type path: str.
        :param includelogs: Flag to determine if logs should be downloaded as well in the crawl.
        :type includelogs: bool
        :param init: Flag to determine if this is the initial load.
        :type init: bool
        :param crawl: Flag to determine if load should crawl through found links.
        :type crawl: bool
        :param loadtype: Flag to determine if loading standard links: *href* or schema links: *ref*.
        :type loadtype: str.
        :param loadcomplete: Flag to download the entire data model including registries and
                             schemas.
        :type loadcomplete: bool
        :param path_refresh: Flag to reload the path specified, clearing any patches and overwriting the
                    current data in the monolith.
        :type path_refresh: bool
        """
        if init:
            if LOGGER.getEffectiveLevel() >= 20 and not json_out:
                sys.stdout.write("Discovering data...")
            else:
                LOGGER.info("Discovering data...")
            self.name = self.name + " at %s" % self.client.base_url

        selectivepath = path
        if not selectivepath:
            selectivepath = self.client.default_prefix
        if loadtype == "href" and not self.client.base_url.startswith("blobstore://.") and not single:
            if not self.threads:
                for _ in range(6):
                    workhand = LoadWorker(self.get_queue)
                    workhand.setDaemon(True)
                    workhand.start()
                    self.threads.append(workhand)

            self.get_queue.put(
                (
                    selectivepath,
                    includelogs,
                    loadcomplete,
                    crawl,
                    path_refresh,
                    init,
                    None,
                    None,
                    self,
                )
            )
            self.get_queue.join()

            # Raise any errors from threads, and set them back to None after
            excp = None
            for thread in self.threads:
                if excp is None:
                    excp = thread.get_exception()
                thread.exception = None

            if excp:
                raise excp

            # self.member_queue.join()
        else:
            # We can't load ref or local client in a threaded manner
            self._load(
                selectivepath,
                originaluri=None,
                crawl=crawl,
                includelogs=includelogs,
                init=init,
                loadtype=loadtype,
                loadcomplete=loadcomplete,
                path_refresh=path_refresh,
                prevpath=None,
            )

        if init:
            if LOGGER.getEffectiveLevel() >= 20 and not json_out:
                sys.stdout.write("Done\n")
            else:
                LOGGER.info("Done\n")
        if self.directory_load and init:
            self._populatecollections()

    def loadallconfig(
        self,
        path=None,
        includelogs=False,
        init=False,
        crawl=True,
        loadtype="href",
        loadcomplete=False,
        path_refresh=False,
        json_out=False,
        single=True,
    ):
        """Walks the entire data model and caches all responses or loads an individual path into
        the monolith. Supports both threaded and sequential crawling.

        :param path: The path to start the crawl from the provided path if crawling or
                     loads the path into monolith. If path is not included, crawl will start with
                     the default. The default is */redfish/v1/* or */rest/v1* depending on if the
                     system is Redfish or LegacyRest.
        :type path: str.
        :param includelogs: Flag to determine if logs should be downloaded as well in the crawl.
        :type includelogs: bool
        :param init: Flag to determine if this is the initial load.
        :type init: bool
        :param crawl: Flag to determine if load should crawl through found links.
        :type crawl: bool
        :param loadtype: Flag to determine if loading standard links: *href* or schema links: *ref*.
        :type loadtype: str.
        :param loadcomplete: Flag to download the entire data model including registries and
                             schemas.
        :type loadcomplete: bool
        :param path_refresh: Flag to reload the path specified, clearing any patches and overwriting the
                    current data in the monolith.
        :type path_refresh: bool
        """

        selectivepath = path
        if not selectivepath:
            selectivepath = self.client.default_prefix
        self._load(
            selectivepath,
            originaluri=None,
            crawl=crawl,
            includelogs=includelogs,
            init=init,
            loadtype=loadtype,
            loadcomplete=loadcomplete,
            path_refresh=path_refresh,
            prevpath=None,
        )

        if init:
            if LOGGER.getEffectiveLevel() >= 20 and not json_out:
                sys.stdout.write("Done\n")
            else:
                LOGGER.info("Done\n")
        if self.directory_load and init:
            self._populatecollections()

    def _load(
        self,
        path,
        crawl=True,
        originaluri=None,
        includelogs=False,
        init=True,
        loadtype="href",
        loadcomplete=False,
        path_refresh=False,
        prevpath=None,
    ):
        """Sequential version of loading monolith and parsing schemas.

        :param path: path to start load from.
        :type path: str
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: bool
        :param originaluri: variable to assist in determining originating path.
        :type originaluri: str
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: bool
        :param init: flag to determine if first run of load.
        :type init: bool
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: bool
        :param path_refresh: flag to reload the members in the monolith instead of skip if they exist.
        :type path_refresh: bool
        """

        if (path.endswith("?page=1") or path.endswith(".json")) and not loadcomplete:
            # Don't download schemas in crawl unless we are loading absolutely everything
            return
        elif path == "/" or "telemetry" in path.lower() or not path.startswith("/redfish/v1"):
            return
        elif not includelogs:
            # Only include logs when asked as there can be an extreme amount of entries
            if "/log" in path.lower():
                return

        # remove fragments and quote characters in path
        p = urlparse(path)
        p = ParseResult(
            scheme=p.scheme, netloc=p.netloc, path=quote(p.path), params=p.params, query=p.query, fragment=""
        )
        path = urlunparse(p)

        if prevpath and prevpath != path:
            self.ctree[prevpath].update([path])
        if not path_refresh:
            if path.lower() in self.visited_urls:
                return
        LOGGER.debug("_loading %s", path)

        resp = self.client.get(path)
        if resp.status != 200 and path.lower() == self.typepath.defs.biospath:
            raise BiosUnregisteredError()
        elif resp.status == 401:
            raise SessionExpired("Invalid session. Please logout and " "log back in or include credentials.")
        elif resp.status not in (201, 200):
            self.removepath(path)
            return

        if loadtype == "ref":
            try:
                if resp.status in (201, 200):
                    self.update_member(resp=resp, path=path, init=init)
                self._parse_schema(resp)
            except jsonpointer.JsonPointerException:
                raise SchemaValidationError()

        self.update_member(resp=resp, path=path, init=init)

        fpath = lambda pa, path: (
            path if pa.endswith(self.typepath.defs.hrefstring) and pa.startswith((self.collstr, "Entries")) else None
        )

        if loadtype == "href":
            # follow all the href attributes
            if self.is_redfish:
                jsonpath_expr = jsonpath_rw.parse("$..'@odata.id'")
            else:
                jsonpath_expr = jsonpath_rw.parse("$..href")
            matches = jsonpath_expr.find(resp.dict)

            if "links" in resp.dict and "NextPage" in resp.dict["links"]:
                if originaluri:
                    next_link_uri = originaluri + "?page=" + str(resp.dict["links"]["NextPage"]["page"])
                    href = "%s" % next_link_uri

                    self._load(
                        href,
                        originaluri=originaluri,
                        includelogs=includelogs,
                        crawl=crawl,
                        init=init,
                        prevpath=None,
                        loadcomplete=loadcomplete,
                    )
                else:
                    next_link_uri = path + "?page=" + str(resp.dict["links"]["NextPage"]["page"])

                    href = "%s" % next_link_uri
                    self._load(
                        href,
                        originaluri=path,
                        includelogs=includelogs,
                        crawl=crawl,
                        init=init,
                        prevpath=None,
                        loadcomplete=loadcomplete,
                    )

            # Only use monolith if we are set to
            matchrdirpath = (
                next((match for match in matches if match.value == self._resourcedir), None)
                if self.directory_load
                else None
            )
            if not matchrdirpath and crawl:
                for match in matches:
                    if path == "/rest/v1" and not loadcomplete:
                        if (
                            str(match.full_path) == "links.Schemas.href"
                            or str(match.full_path) == "links.Registries.href"
                        ):
                            continue
                    elif not loadcomplete:
                        if (
                            str(match.full_path) == "Registries.@odata.id"
                            or str(match.full_path) == "JsonSchemas.@odata.id"
                        ):
                            continue

                    if match.value == path:
                        continue
                    elif not isinstance(match.value, six.string_types):
                        continue

                    href = "%s" % match.value
                    self._load(
                        href,
                        crawl=crawl,
                        originaluri=originaluri,
                        includelogs=includelogs,
                        init=init,
                        prevpath=fpath(str(match.full_path), path),
                        loadcomplete=loadcomplete,
                    )
            elif crawl:
                href = "%s" % matchrdirpath.value
                self._load(
                    href,
                    crawl=crawl,
                    originaluri=originaluri,
                    includelogs=includelogs,
                    init=init,
                    prevpath=path,
                    loadcomplete=loadcomplete,
                )
            if loadcomplete:
                if path == "/rest/v1":
                    schemamatch = jsonpath_rw.parse("$..extref")
                else:
                    schemamatch = jsonpath_rw.parse("$..Uri")
                smatches = schemamatch.find(resp.dict)
                matches = matches + smatches
                for match in matches:
                    if isinstance(match.value, six.string_types):
                        self._load(
                            match.value,
                            crawl=crawl,
                            originaluri=originaluri,
                            includelogs=includelogs,
                            init=init,
                            loadcomplete=loadcomplete,
                            prevpath=fpath(str(match.full_path), path),
                        )

    def _parse_schema(self, resp):
        """Function to get and replace schema $ref with data

        :param resp: response data containing ref items.
        :type resp: str
        """
        # pylint: disable=maybe-no-member
        if not self.typepath.gencompany:
            return self._parse_schema_gen(resp)
        jsonpath_expr = jsonpath_rw.parse('$.."$ref"')
        matches = jsonpath_expr.find(resp.dict)
        respcopy = resp.dict
        typeregex = r"([#,@].*?\.)"
        if matches:
            for match in matches:
                fullpath = str(match.full_path)
                jsonfile = match.value.split("#")[0]
                jsonpath = match.value.split("#")[1]
                listmatch = None
                found = None

                if "redfish.dmtf.org" in jsonfile:
                    if "odata" in jsonfile:
                        jsonpath = jsonpath.replace(jsonpath.split("/")[-1], "odata" + jsonpath.split("/")[-1])
                    jsonfile = "Resource.json"

                found = re.search(typeregex, fullpath)
                if found:
                    repitem = fullpath[found.regs[0][0] : found.regs[0][1]]
                    schemapath = "/" + fullpath.replace(repitem, "~").replace(".", "/").replace("~", repitem)
                else:
                    schemapath = "/" + fullpath.replace(".", "/")

                if ".json" in jsonfile:
                    itempath = schemapath

                    if self.is_redfish:
                        if resp.request.path[-1] == "/":
                            newpath = "/".join(resp.request.path.split("/")[:-2]) + "/" + jsonfile + "/"
                        else:
                            newpath = "/".join(resp.request.path.split("/")[:-1]) + "/" + jsonfile + "/"
                    else:
                        newpath = "/".join(resp.request.path.split("/")[:-1]) + "/" + jsonfile

                    if "href.json" in newpath:
                        continue

                    if newpath.lower() not in self.visited_urls:
                        self.load(
                            newpath,
                            crawl=False,
                            includelogs=False,
                            init=False,
                            loadtype="ref",
                        )

                    instance = list()

                    # deprecated type "string" for Type.json
                    if "string" in self.types:
                        for item in self.iter("string"):
                            instance.append(item)
                    if "object" in self.types:
                        for item in self.iter("object"):
                            instance.append(item)

                    for item in instance:
                        if jsonfile in item.path:
                            if "anyOf" in fullpath:
                                break

                            dictcopy = item.dict
                            try:
                                # TODO may need to really verify this is acceptable regex
                                listmatch = re.search("[][0-9]+[]", itempath)
                            except regexerr:
                                pass
                                # LOGGER.info("An error occurred with regex match on path: %s\n%s\n"\
                                #            % (itempath, str(excp)))

                            if listmatch:
                                start = listmatch.regs[0][0]
                                end = listmatch.regs[0][1]

                                newitempath = [itempath[:start], itempath[end:]]
                                start = jsonpointer.JsonPointer(newitempath[0])
                                end = jsonpointer.JsonPointer(newitempath[1])

                                del start.parts[-1], end.parts[-1]
                                vals = start.resolve(respcopy)

                                count = 0

                                for val in vals:
                                    try:
                                        if "$ref" in six.iterkeys(end.resolve(val)):
                                            end.resolve(val).pop("$ref")
                                            end.resolve(val).update(dictcopy)
                                            replace_pointer = jsonpointer.JsonPointer(end.path + jsonpath)

                                            data = replace_pointer.resolve(val)
                                            set_pointer(val, end.path, data)
                                            start.resolve(respcopy)[count].update(val)

                                            break
                                    except:
                                        count += 1
                            else:
                                itempath = jsonpointer.JsonPointer(itempath)
                                del itempath.parts[-1]

                                try:
                                    if "$ref" in six.iterkeys(itempath.resolve(respcopy)):
                                        itempath.resolve(respcopy).pop("$ref")
                                        itempath.resolve(respcopy).update(dictcopy)
                                        break
                                except jsonpointer.JsonPointerException:
                                    pass

                if jsonpath:
                    if "anyOf" in fullpath:
                        continue

                    if not jsonfile:
                        replacepath = jsonpointer.JsonPointer(jsonpath)
                        schemapath = schemapath.replace("/$ref", "")
                        if re.search(r"\[\d]", schemapath):
                            schemapath = schemapath.translate(str.maketrans("", "", "[]"))
                        schemapath = jsonpointer.JsonPointer(schemapath)
                        data = replacepath.resolve(respcopy)

                        if "$ref" in schemapath.resolve(respcopy):
                            schemapath.resolve(respcopy).pop("$ref")
                            schemapath.resolve(respcopy).update(data)

                    else:
                        if not listmatch:
                            schemapath = schemapath.replace("/$ref", "")
                            replacepath = schemapath + jsonpath
                            replace_pointer = jsonpointer.JsonPointer(replacepath)
                            try:
                                data = replace_pointer.resolve(respcopy)
                                set_pointer(respcopy, schemapath, data)
                            except jsonpointer.JsonPointerException:
                                # TODO
                                pass

            resp.loaddict(respcopy)
        else:
            resp.loaddict(respcopy)

    def _parse_schema_gen(self, resp):
        """Redfish general function to get and replace schema $ref with data

        :param resp: response data containing ref items.
        :type resp: str

        """
        # pylint: disable=maybe-no-member
        getval = lambda inmat: getval(inmat.left) + "/" + str(inmat.right) if hasattr(inmat, "left") else str(inmat)
        respcopy = resp.dict
        jsonpath_expr = jsonpath_rw.parse('$.."anyOf"')
        while True:
            matches = jsonpath_expr.find(respcopy)
            if not matches:
                break
            match = matches[0]
            newval = None
            schlist = match.value
            schlist = [ele for ele in list(schlist) if ele != {"type": "null"}]
            norefsch = [ele for ele in list(schlist) if isinstance(ele, dict) and len(ele.keys()) > 1]
            if norefsch:
                newval = norefsch[0]
            else:
                newsc = [ele for ele in list(schlist) if not ele["$ref"].split("#")[0]]
                newval = newsc[0] if newsc else None
                if not newval:
                    schlist = [
                        ele["$ref"]
                        for ele in list(schlist)
                        if "$ref" in ele.keys()
                        and (ele["$ref"].split("#")[0].endswith(".json") and "odata" not in ele["$ref"].split("#")[0])
                    ]
                    maxsch = max(schlist)
                    newval = {"$ref": maxsch}

            itempath = "/" + getval(match.full_path)
            if re.search(r"\[\d+]", itempath):
                itempath = itempath.translate(str.maketrans("", "", "[]"))
            itempath = jsonpointer.JsonPointer(itempath)
            del itempath.parts[-1]
            if "anyOf" in six.iterkeys(itempath.resolve(respcopy)):
                itempath.resolve(respcopy).pop("anyOf")
                itempath.resolve(respcopy).update(newval)

        jsonpath_expr = jsonpath_rw.parse('$.."$ref"')
        matches = jsonpath_expr.find(respcopy)
        if matches:
            for _, match in enumerate(matches):
                jsonfile = match.value.split("#")[0]
                jsonfile = "" if jsonfile.lower() == resp.request.path.lower() else jsonfile
                jsonpath = match.value.split("#")[1]

                schemapath = "/" + getval(match.full_path)
                if jsonfile:
                    itempath = schemapath
                    if "/" not in jsonfile:
                        inds = -2 if resp.request.path[-1] == "/" else -1
                        jsonfile = "/".join(resp.request.path.split("/")[:inds]) + "/" + jsonfile + "/"
                    if jsonfile not in self.paths:
                        self.load(
                            jsonfile,
                            crawl=False,
                            includelogs=False,
                            init=False,
                            loadtype="ref",
                        )
                    item = self.paths[jsonfile] if jsonfile in self.paths else None

                    if not item:
                        if "anyOf" not in schemapath:
                            raise SchemaValidationError()
                        continue
                    if re.search(r"\[\d+]", itempath):
                        itempath = itempath.translate(str.maketrans("", "", "[]"))
                    itempath = jsonpointer.JsonPointer(itempath)
                    del itempath.parts[-1]
                    try:
                        if "$ref" in six.iterkeys(itempath.resolve(respcopy)):
                            itempath.resolve(respcopy).pop("$ref")
                            itempath.resolve(respcopy).update(item.dict)
                    except jsonpointer.JsonPointerException:
                        pass

                if jsonpath:
                    schemapath = schemapath.replace("/$ref", "")
                    if re.search(r"\[\d+]", schemapath):
                        schemapath = schemapath.translate(str.maketrans("", "", "[]"))
                    if not jsonfile:
                        replacepath = jsonpointer.JsonPointer(jsonpath)
                        schemapath = jsonpointer.JsonPointer(schemapath)
                        data = replacepath.resolve(respcopy)
                        if "$ref" in schemapath.resolve(respcopy):
                            schemapath.resolve(respcopy).pop("$ref")
                            schemapath.resolve(respcopy).update(data)
                    else:
                        replacepath = schemapath + jsonpath
                        replace_pointer = jsonpointer.JsonPointer(replacepath)
                        data = replace_pointer.resolve(respcopy)
                        set_pointer(respcopy, schemapath, data)

            resp.loaddict(respcopy)
        else:
            resp.loaddict(respcopy)

    def load_from_dict(self, src):
        """Load data to monolith from a dict. This is the reverse of :func:`to_dict`.

        :param src: data receive from rest operation.
        :type src: str

        """
        self._type = src["Type"]
        self._name = src["Name"]
        self.typesadded = defaultdict(set, {ki: set(val) for ki, val in src["typepath"].items()})
        self.ctree = defaultdict(set, {ki: set(val) for ki, val in src["ctree"].items()})
        self.colltypes = defaultdict(set, {ki: set(val) for ki, val in src["colls"].items()})
        for _, resp in list(src["resps"].items()):
            member = RisMonolithMemberv100(None, self.is_redfish)
            member.load_from_dict(resp)
            self.update_member(member=member, init=False)

    def to_dict(self):
        """Convert data to a dict from monolith. This is the reverse of :func:`load_from_dict`."""
        result = OrderedDict()
        result["Type"] = self.type
        result["Name"] = self.name
        result["typepath"] = self.typesadded
        result["ctree"] = self.ctree
        result["colls"] = self.colltypes
        result["resps"] = {x: v.to_dict() for x, v in list(self.paths.items())}
        return result

    def markmodified(self, opath, path=None, modpaths=None):
        """Mark the paths to be modifed which are connected to current path. When calling this
        function you only need to include `opath`.

        :param opath: original path which has been modified
        :type opath: str
        """
        modpaths = set() if modpaths is None else modpaths
        path = path if path else opath
        if not path:
            return
        modpaths.update(self.ctree[path] if path in self.ctree else set())
        self.paths[path].modified = True
        for npath in [
            unmodpath for unmodpath in modpaths if unmodpath in self.paths and not self.paths[unmodpath].modified
        ]:
            self.markmodified(opath, path=npath, modpaths=modpaths)
        return modpaths

    def checkmodified(self, opath, path=None, modpaths=None):
        """Check if the path or its children are modified. When calling this
        function you only need to include `opath`.

        :param opath: original path which has been modified
        :type opath: str
        """
        # return [paths for paths in self.ctree[path] if self.paths[paths].modified]
        modpaths = set() if modpaths is None else modpaths
        path = path if path else opath
        newpaths = set()
        if not path:
            return
        if path in self.paths and self.paths[path].modified:
            newpaths = (
                set([conn for conn in self.ctree[path] if conn in self.paths and self.paths[path].modified]) - modpaths
            )
            modpaths.update(newpaths | set([path]))
        for npath in [unmodpath for unmodpath in newpaths]:
            self.checkmodified(opath, path=npath, modpaths=modpaths)
        return modpaths

    def removepath(self, path):
        """Remove a given path from the cache

        :param path: path which is to be checked if modified
        :type path: str
        """
        if path in self._visited_urls:
            self._visited_urls.remove(path)
        if path not in self.paths:
            return
        if path in self.typesadded[self.paths[path].maj_type]:
            self.typesadded[self.paths[path].maj_type].remove(path)
        if not self.typesadded[self.paths[path].maj_type]:
            del self.typesadded[self.paths[path].maj_type]
        del self.paths[path]
        if path in self.ctree:
            del self.ctree[path]
        _ = [self.ctree[paths].remove(path) for paths in self.ctree if path in self.ctree[paths]]

    def _populatecollections(self):
        """Populate the collections type and types depending on resourcedirectory"""
        if self._resourcedir not in self.paths:
            return
        self.colltypes = defaultdict(set)
        alltypes = []
        colls = []
        for item in self.paths[self._resourcedir].dict["Instances"]:
            # Fix for incorrect RDir instances.
            if self.typepath.defs.typestring not in item or item[self.typepath.defs.hrefstring] in self.paths:
                continue
            typename = ".".join(item[self.typepath.defs.typestring].split(".", 2)[:2]).split("#")[-1]
            _ = [alltypes.append(typename) if "Collection" not in typename else None]
            _ = [colls.append(typename) if "Collection" in typename else None]
            member = RisMonolithMemberv100(None, self.is_redfish)
            member.popdefs(typename, item[self.typepath.defs.hrefstring], item[self.etagstr])
            self.update_member(member=member, init=False)
        for coll in colls:
            collname = coll.split("Collection")[0].split("#")[-1]
            typename = next((name for name in alltypes if name.startswith(collname)), None)
            colltype = ".".join(coll.split(".", 2)[:2]).split("#")[-1]
            self.colltypes[typename].add(colltype)

    def capture(self, redmono=False, single=True):
        """Crawls the server and returns the monolith data or just headers and responses.

        :param redmono: If True, returns only headers and responses; otherwise, returns full monolith data.
        :type redmono: bool
        :rtype: dict
        """
        self.load(includelogs=False, crawl=True, loadcomplete=True, path_refresh=True, init=True, single=single)

        if not redmono:
            return self.to_dict()

        ret = {}
        try:
            for x, v in self.paths.items():
                if v:
                    v_resp = v.resp
                    if v_resp:
                        ret[x] = {"Headers": v_resp.getheaders(), "Response": v_resp.dict}
        except Exception as e:
            LOGGER.debug("Error in capture: %s", e)
            ret = {}
        return ret

    def normalize_urls(self, data):
        """
        Normalize URL-like dictionary keys:
        - If both '/path' and '/path/' exist, keep only '/path/'.
        - If only one version exists, ensure the key ends with '/'.
        - All final keys end with '/'.
        """
        normalized_data = {}
        seen = set()

        for key in data:
            # Normalize key with trailing slash
            if key.endswith("/"):
                base_key = key[:-1]
                trailing_key = key
            else:
                base_key = key
                trailing_key = key + "/"

            # Avoid processing the same base path twice
            if base_key in seen:
                continue
            seen.add(base_key)

            # Prefer version with trailing slash
            if trailing_key in data:
                normalized_data[trailing_key] = data[trailing_key]
            elif base_key in data:
                normalized_data[trailing_key] = data[base_key]

        return normalized_data

    def fetch_data(self, path):
        resp = self.client.get(path)
        return resp

    def captureallconfig(self, single=True, exclueurl=None):
        """Crawls the server and returns the monolith data or just headers and responses.

        :param redmono: If True, returns only headers and responses; otherwise, returns full monolith data.
        :type redmono: bool
        :rtype: dict
        """
        self.loadallconfig(
            includelogs=False, crawl=True, loadcomplete=True, path_refresh=True, init=True, single=single
        )

        ret = {}

        try:
            for x, v in self.paths.items():
                if exclueurl.lower() != x.lower():
                    if v:
                        if v.resp is not None:
                            ret[x] = {"Headers": v.resp.getheaders(), "Response": v.resp.dict}
                        else:
                            resp = self.fetch_data(x)
                            ret[x] = {"Headers": resp.getheaders(), "Response": resp.dict}
        except Exception as e:
            LOGGER.debug("Error in capture: %s", e)
            ret = {}
        ret = self.normalize_urls(ret)
        return ret

    def killthreads(self):
        """Function to kill threads on logout"""
        threads = []
        for thread in threading.enumerate():
            if isinstance(thread, LoadWorker):
                self.get_queue.put(
                    (
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                        "KILL",
                    )
                )
                threads.append(thread)

        for thread in threads:
            thread.join()

    def _update_progress(self):
        """Simple function to increment the dot progress"""
        if self.progress % 6 == 0:
            sys.stdout.write(".")
