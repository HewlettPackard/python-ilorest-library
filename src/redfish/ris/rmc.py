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

"""A convenience layer that combines multiple lower level classes and functions into one."""

import copy
import hashlib
import logging
import shutil

# ---------Imports---------
import sys
import time

import six

try:
    from collections import OrderedDict
except ImportError:
    from collections.abc import OrderedDict

import jsonpatch
import jsonpointer

import redfish.ris.gen_compat
import redfish.ris.validation
from redfish.rest.v1 import RestClient
from redfish.ris.resp_handler import ResponseHandler
from redfish.ris.ris import RisMonolith, SchemaValidationError, SessionExpired
from redfish.ris.rmc_helper import (
    EmptyRaiseForEAFP,
    IloResponseError,
    IncompatibleiLOVersionError,
    InstanceNotFoundError,
    LoadSkipSettingError,
    NothingSelectedError,
    NothingSelectedSetError,
    RmcFileCacheManager,
    UndefinedClientError,
    ValidationError,
    ValueChangedError,
)
from redfish.ris.utils import (
    checkallowablevalues,
    diffdict,
    getattributeregistry,
    iterateandclear,
    merge_dict,
    navigatejson,
    print_handler,
    skipnonsettingsinst,
    validate_headers,
    warning_handler,
)
from redfish.ris.validation import Typepathforval, ValidationManager
from redfish.hpilo.vnichpilo import AppAccount

# ---------End of imports---------

# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class RmcApp(object):
    """A convenience class that combines the client, compatibility, validation, caching,
    and monolith into one class.

    :param showwarnings: Flag to print warnings to std.out (True) or log in log file (False)
    :type showwarnings: bool
    :param cache_dir: Cache directory to save cache data to, if None, RmcApp will not cache data.
                      Cache can allow your RmcApp to persist between scripts.
    :type cache_dir: str
    """

    def __init__(self, showwarnings=False, cache_dir=None):
        self.logger = LOGGER
        self.redfishinst = None
        self.sessioninst = None
        self._cm = RmcFileCacheManager(self)
        self.monolith = None
        self._iloversion = None
        self._validationmanager = None
        self._selector = None
        self._cachedir = cache_dir
        self.verbose = 1
        self._sessionid = None
        self.typepath = redfish.ris.gen_compat.Typesandpathdefines()
        Typepathforval(typepathobj=self.typepath)

        if not showwarnings:
            self.logger.setLevel(logging.WARNING)
            if self.logger.handlers and self.logger.handlers[0].name == "lerr":
                self.logger.handlers.remove(self.logger.handlers[0])

    @property
    def monolith(self):
        """Get the monolith from the current client"""
        return self._monolith

    @monolith.setter
    def monolith(self, monolith):
        """Set the monolith"""
        self._monolith = monolith

    @property
    def current_client(self):
        """Get the current client"""
        if self.redfishinst:
            return self.redfishinst
        raise UndefinedClientError()

    @property
    def validationmanager(self):
        """Get the valdation manager"""
        if self.getiloversion():
            if self._validationmanager:
                self._validationmanager.reset_errors_warnings()
            else:
                monolith = self.monolith
                self._validationmanager = ValidationManager(monolith, defines=self.typepath)
            self._validationmanager.updatevalidationdata()
        else:
            self._validationmanager = None
        return self._validationmanager

    @property
    def selector(self):
        """The selector that will be used to gather data if no selector or instance argument is
        passed."""
        return self._selector

    @selector.setter
    def selector(self, sel):
        """Set the selector"""
        self._selector = sel

    @property
    def cachedir(self):
        """The cache directory that is used to cache app data to a file,
        None if not caching data."""
        return self._cachedir

    @cachedir.setter
    def cachedir(self, cache_dir):
        """Set the cachedir"""
        self._cachedir = cache_dir

    @property
    def cache(self):
        """True if we are caching data, False if we are not"""
        return True if self.cachedir else False

    def restore(self, creds=None, enc=False):
        """Restores the monolith from cache. Used to load a monolith data back into a new app
        class. Keyword arguments are only needed in a local client when in a high security mode.

        :param creds: Credentials to create the client with.
        :type creds: str
        :param enc: Flag to determine if encoding functions are being used. True if being used false
                    if not.
        :type enc: bool
        """
        self._cm.uncache_rmc(creds=creds, enc=enc)

    def set_encode_funct(self, funct):
        """Set the encoding function for cache to use. Can be used to protect sensitive data when
        it is at rest.

        :param funct: The function to use for encoding data
        :type funct: function
        """
        self._cm.encodefunct = funct

    def set_decode_funct(self, funct):
        """Set the decoding function for cache to use. Is used in conjunction with the
        `set_encode_funct` to turn the encoded data back into a usable string.

        :param funct: The function to use for decoding data
        :type funct: function
        """
        self._cm.decodefunct = funct

    def save(self):
        """Updates the cache with the latest monolith data."""
        self._cm.cache_rmc()

    def login(
        self,
        username=None,
        password=None,
        sessionid=None,
        base_url="blobstore://.",
        path=None,
        skipbuild=False,
        includelogs=False,
        biospassword=None,
        is_redfish=False,
        proxy=None,
        ssl_cert=None,
        user_ca_cert_data=None,
        json_out=False,
        login_otp=None,
        log_dir=None,
        session_location=None,
        cache=True,
    ):
        """Performs a login on a the server specified by the keyword arguments. Will also create
        a monolith, client, and update the compatibility classes for the app instance. If base_url
        is not included the login is assumed to be locally on the OS.

        :param username: The user name required to login to server.
        :type: str
        :param password: The password credentials required to login.
        :type password: str
        :param base_url: The redfish host name or ip address to login to.
        :type base_url: str
        :param path: The path to initiate the monolith crawl from. If None, it will start from the
                     root. See monolith documentation on how the path is used.
        :type path: str
        :param proxy: The proxy required for connection (if any).
        :type proxy: str
        :param ssl_cert: The path to the CA bundle or SSL certificate to use with connection
                        (if any).
        :type ssl_cert: str
        :param user_ca_cert_data: Dictionary of user certificate data for iLO Certificate-based
          authentication including iLO User TLS certificate, iLO User CA Root Key, \
          iLO User CA Root Key Password (for encrypted CAs)
        :type: user_ca_pass: str
        :param skipbuild: The flag to determine monolith download. If True, monolith will be
                          initiated empty, if False will build the monolith.
        :type skipbuild: bool
        :param includelogs: The flag to determine id logs should be downloaded in the crawl.
        :type includelogs: bool
        :param biospassword: The BIOS password for the server if set.
        :type biospassword: str
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request. Only required if the system has both LegacyREST and Redfish.
        :type is_redfish: bool
        """


        self.typepath.getgen(
            url=base_url,
            username=username,
            password=password,
            sessionid=sessionid,
            ca_cert_data=user_ca_cert_data,
            proxy=proxy,
            isredfish=is_redfish,
            login_otp=login_otp,
            log_dir=log_dir,
            session_location=session_location
        )
        if cache:
            if user_ca_cert_data and self.typepath.iloversion < 5.23:
                raise IncompatibleiLOVersionError(
                    "Certificate based login is incompatible with this " "iLO version: %s\n" % self.typepath.iloversion
                )
            is_redfish = self.typepath.updatedefinesflag(redfishflag=is_redfish)

            if self.redfishinst and self.redfishinst.session_key:
                self.logout()
            def_prefix = self.typepath.defs.startpath
        else:
            def_prefix = "/redfish/v1"

        self.redfishinst = RestClient(
            base_url=base_url,
            username=username,
            password=password,
            session_key=sessionid,
            default_prefix=def_prefix,
            biospassword=biospassword,
            is_redfish=is_redfish,
            proxy=proxy,
            ca_cert_data=user_ca_cert_data,
            login_otp=login_otp,
            log_dir=log_dir,
            session_location=session_location,
        )

        self.current_client.login(self.current_client.auth_type)
        if cache:
            resp = self.get_handler(self.typepath.defs.managerpath, service=False, silent=True).dict
            ver = resp["FirmwareVersion"]
            if "iLO" not in ver:
                self.typepath.ilover = (ver.split(" ")[0])
                self.typepath.ilover = float(self.typepath.ilover.replace('.', ''))
            inittime = time.time()

            self._build_monolith(path=path, includelogs=includelogs, skipbuild=skipbuild, json_out=json_out)
            endtime = time.time()

            if self.verbose > 1:
                sys.stdout.write("Monolith build process time: %s\n" % (endtime - inittime))
            self.save()
            if not self.monolith:
                self.monolith.update_member(
                    resp=self.current_client.root,
                    path=self.typepath.defs.startpath,
                    init=False,
                )

    def logout(self, url=None):
        """Performs a logout of the server and prepares the app for another system, setting app
        variables to default values.

        :param url: The URL for the logout request. Only needed when using a cache.
        :type url: str
        """
        sessionlocs = []
        self._validationmanager = None
        self._iloversion = None

        try:
            self.monolith.killthreads()
        except Exception:
            pass

        try:
            self.current_client.logout()
        except Exception:
            sessionlocs = self._cm.logout_del_function(url)
        else:
            self._cm.logout_del_function(url)

        for session in sessionlocs:
            try:
                self.delete_handler(session[0], silent=True, service=True)
            except:
                pass
        self.redfishinst = None

        cachedir = self.cachedir
        if cachedir:
            try:
                shutil.rmtree(cachedir)
            except Exception:
                pass

    def select(self, selector=None, fltrvals=(None, None), path_refresh=False):
        """Selects instances based on selector and filter values. The select specified is saved in
        the app for further use. If another selector is sent, it overwrites the current one.

        :param selector: The type (@odata.type for Redfish) to select.
        :type selector: str
        :param fltrvals: The filter values for the select operation (Key,Val). If a selector returns
                         multiple instances fltrvals can filter the instances by a key/value pair,
                         limiting the returned instances to the one you want.
        :type fltrvals: tuple
        :param path_refresh: The flag to reload the selected instances. If True, each instance will be
                    grabbed again from the server to make sure responses are up to date.
        :type path_refresh: bool
        :returns: A list of selected monolith member instances.
        :rtype: RisMonolithMemberv100
        """
        if not selector:
            selector = self.selector
        # Still nothing selected and selector is NULL
        if not selector:
            raise NothingSelectedError()
        selector = self.typepath.modifyselectorforgen(selector)
        instances = self._getinstances(selector=selector, path_refresh=path_refresh)
        val = fltrvals[1].strip("'\"") if isinstance(fltrvals[1], six.string_types) else fltrvals[1]
        instances = [
            inst
            for inst in instances
            if not fltrvals[0] or navigatejson(fltrvals[0].split("/"), copy.deepcopy(inst.dict), val)
        ]
        if any(instances):
            self.selector = selector
            self.save()
            return instances

        errmsg = (
            "Unable to locate instance for '{0}' and filter '{1}={2}'".format(selector, fltrvals[0], fltrvals[1])
            if fltrvals[0] and fltrvals[1]
            else "Unable to locate instance for {}\n".format(selector)
        )

        raise InstanceNotFoundError(errmsg)

    def types(self, fulltypes=False):
        """Returns a list of types available to be queried and selected with monolith.

        :param fulltypes: Flag to determine if types return Redfish full name, if False will return
                          a shortened version of the type string.
        :type fulltypes: bool
        :returns: A list of type strings.
        :rtype: list
        """
        instances = list()

        if self.monolith:
            monolith = self.monolith
            rdirtype = next(monolith.gettypename(self.typepath.defs.resourcedirectorytype), None)

            if not rdirtype:
                for inst in monolith.iter():
                    if not any([x for x in ["ExtendedError", "object", "string"] if x in inst.type]):
                        instances.append(inst.type)
            else:
                for instance in monolith.iter(rdirtype):
                    for item in instance.resp.dict["Instances"]:
                        if (
                            item
                            and instance._typestring in list(item.keys())
                            and "ExtendedError" not in item[instance._typestring]
                        ):
                            if not fulltypes and instance._typestring == "@odata.type":
                                tval = item["@odata.type"].split("#")
                                tval = tval[-1].split(".")[:-1]
                                tval = ".".join(tval)
                                instances.append(tval)
                            elif item:
                                instances.append(item[instance._typestring])
        return instances

    def getprops(
        self,
        selector=None,
        props=None,
        nocontent=None,
        skipnonsetting=True,
        remread=False,
        insts=None,
    ):
        """Gets properties from a specified selector. If no selector is specified, uses the selector
        property in the app class. Instead of a selector a list of instances to search can be used
        instead. If both **selector** and **insts** are passed, **insts** is used.

        Specific values for multi-level dictionaries can be returned by passing each key
        separated by a "/" Ex: Key/Sub-Key/Sub-Sub-Key

        :param selector: The type selection for the get operation.
        :type selector: str
        :param skipnonsetting: Flag to remove non settings path.
        :type skipnonsetting: bool
        :param nocontent: Keys not found are added to the list provided.
        :type nocontent: list
        :param remread: Flag to remove readonly properties.
        :type remread: bool
        :param props: The keys to search for within current selection.
        :type props: list
        :param insts: List of RisMonolithMemberv100 to be searched for specific keys.
        :type insts: list
        :returns: A list of properties found in dictionary form.
        :rtype: list
        """
        results = list()
        nocontent = set() if nocontent is None else nocontent
        if props:
            if isinstance(props, list):
                noprop = {prop: False for prop in props}
            else:
                noprop = {props: False}
        else:
            noprop = {}
        instances = insts if insts else self._getinstances(selector=selector)
        instances = skipnonsettingsinst(instances) if skipnonsetting else instances

        if selector != "UpdateService.":
            if not instances or len(instances) == 0:
                if not selector:
                    raise NothingSelectedError()

        for instance in instances:
            currdict = instance.dict
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)
            _ = self.removereadonlyprops(currdict, emptyraise=True) if remread else None
            temp_dict = dict()
            if props:
                if isinstance(props, six.string_types):
                    props = [props]
                for prop in props:
                    copydict = copy.deepcopy(currdict)
                    propsdict = navigatejson(prop.split("/"), copydict)
                    if propsdict is None:
                        continue
                    noprop[prop] = True
                    merge_dict(temp_dict, propsdict)
                if temp_dict:
                    if temp_dict not in results:
                        results.append(temp_dict)
            else:
                results.append(currdict)
        if props:
            _ = [nocontent.add(prop) for prop in props if not noprop[prop]]
        return results

    def info(self, selector=None, props=None, dumpjson=True, latestschema=False):
        """Gets schema information for properties from a specified selector. If no selector is
        specified, uses the selector property in the app class. If no properties are specified
        the entire schema dictionary is returned in a list.

        :param selector: The type selection for the info operation.
        :type selector: str
        :param props: The keys to gather schema data for within current selection.
        :type props: str or list
        :param dumpjson: Flag to determine if output should be human readable or json schema.
        :type dumpjson: bool
        :param latestschema: Flag to determine if we should drop the schema version when we try to
                             match schema information. If True, the version will be dropped.
        :type latestschema: bool
        :returns: A list of property schema information if dumpjson is True or string if dumpjson is
                  False.
        :rtype: list or string
        """
        model = None
        outdata = ""
        nokey = False
        results = None
        typestring = self.typepath.defs.typestring
        iloversion = self.getiloversion()
        if not iloversion:
            return results
        instances = self._getinstances(selector)
        attributeregistry = getattributeregistry(instances)
        instances = skipnonsettingsinst(instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for inst in instances:
            bsmodel = None
            currdict = inst.resp.dict
            proppath = inst.resp.getheader("Link").split(";")[0].strip("<>") if inst.resp.getheader("Link") else None
            seldict = {}
            if not props:
                model, bsmodel = self.get_model(currdict, attributeregistry, latestschema, proppath=proppath)
                results = model
                break
            if isinstance(props, six.string_types):
                props = props.split("/") if "/" in props else props
                props = [props] if not isinstance(props, (list, tuple)) else props
                seldict = navigatejson(props, copy.deepcopy(currdict))
                if seldict is None:
                    nokey = True
                    continue
            if self.typepath.defs.typestring in currdict:
                seldict[typestring] = currdict[typestring]
                model, bsmodel = self.get_model(
                    currdict,
                    attributeregistry,
                    latestschema,
                    newarg=props[:-1],
                    proppath=proppath,
                )
            if not model and not bsmodel:
                errmsg = "/".join(props)
                warning_handler(
                    "Unable to locate registry model or " "No data available for entry: {}\n".format(errmsg)
                )
                continue
            found = model.get_validator(props[-1]) if model else None
            found = bsmodel.get_validator(props[-1]) if not found and bsmodel else found
            outdata = found if found and dumpjson else found.print_help(props[-1]) if found else outdata

        if outdata or results:
            return outdata if outdata else results

        errmsg = (
            "Entry {} not found in current selection\n".format("/".join(props))
            if nokey
            else "Entry {} not found in current" " selection\n".format("/".join(props))
        )
        warning_handler(errmsg)

    def loadset(
        self,
        seldict=None,
        fltrvals=(None, None),
        diffonly=False,
        latestschema=False,
        uniqueoverride=False,
        selector=None,
    ):
        """Creates json patches in monolith if the supplied dictionary passes schema validation.
        In the event schemas are unavailable the patches are always added. Patches that are created
        this way are not sent to the server until the :meth:`commit` function is called, sending the
        patches to the server. A list of patches that have not been sent to the server can be
        returned with the :meth:`status` function.

        :param selector: The type selection for the loadset operation.
        :type selector: str
        :param seldict: Dictionary with the patches to apply to the selected instances.
        :type seldict: dict
        :param fltrvals: The filter values for the operation (Key,Val). If a selector returns
                         multiple instances fltrvals can filter the instances by a key/value pair,
                         limiting the returned instances to the one you want. If no filter is
                         supplied the patch dictionary will be applied to all instances.
        :type fltrvals: tuple
        :param latestschema: Flag to determine if we should drop the schema version when we try to
                             match schema information. If True, the version will be dropped.
        :type latestschema: bool
        :param diffonly: flag to differentiate only existing properties.
        :type diffonly: bool
        :param uniqueoverride: Flag to determine if system unique properties should also be patched.
                               If this is True, then unique properties will be patched.
        :type uniqueoverride: bool
        :returns: returns a list of properties that have successfully been set
        """
        results = list()
        nochangesmade = False
        settingskipped = [False]

        selector = self.selector if not selector else selector
        instances = self.select(selector=selector, fltrvals=fltrvals)
        attributeregistry = getattributeregistry(instances=instances)
        instances = skipnonsettingsinst(instances=instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        for instance in instances:
            if validate_headers(instance, verbose=self.verbose):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            if "@odata.id" in seldict:
                if currdict["@odata.id"] != seldict["@odata.id"]:
                    continue
            diff_resp = diffdict(
                newdict=copy.deepcopy(seldict),
                oridict=copy.deepcopy(currdict),
                settingskipped=settingskipped,
            )

            iloversion = self.getiloversion()
            if iloversion:
                proppath = (
                    instance.resp.getheader("Link").split(";")[0].strip("<>")
                    if instance.resp.getheader("Link")
                    else None
                )
                try:
                    self._validatechanges(
                        instance=instance,
                        attributeregistry=attributeregistry,
                        newdict=diff_resp,
                        oridict=currdict,
                        unique=uniqueoverride,
                        latestschema=latestschema,
                        proppath=proppath,
                    )
                except SchemaValidationError:
                    LOGGER.error("Cannot validate changes, error found in schema.")

            patches = jsonpatch.make_patch(currdict, diff_resp)

            if patches:
                torem = []
                _ = [torem.append(patch) for patch in patches.patch if patch["op"] == "remove"]
                _ = [patches.patch.remove(patch) for patch in torem]

            for ind, item in enumerate(instance.patches):
                ppath = item.patch[0]["path"] if hasattr(item, "patch") else item[0]["path"]
                # ppath = ["path"](getattr(item, "patch"), item)[0]["path"]
                jpath = jsonpointer.JsonPointer(ppath.lower())
                jval = jpath.resolve(seldict, default="kasjdk?!")
                if not jval == "kasjdk?!":
                    del instance.patches[ind]

            if patches:
                for patch in patches.patch:
                    forprint = patch["value"] if "value" in patch else (patch["op"] + " " + patch["from"])
                    results.append({patch["path"][1:]: forprint})
                if "Managers/1/EthernetInterfaces/1" not in instance.path:
                    self.monolith.path(instance.path).patches.append(patches)
            else:
                nochangesmade = True

        if not nochangesmade:
            return results
        elif settingskipped[0] is True:
            raise LoadSkipSettingError()
        else:
            return results

    def status(self):
        """Returns all pending changes that have not been committed yet."""
        iloversion = self.getiloversion()

        finalresults = list()
        monolith = self.monolith
        (_, _) = self.get_selection(setenable=True)
        attrreg = getattributeregistry([ele for ele in monolith.iter() if ele])
        for instance in monolith.iter():
            results = list()

            if not (instance.patches and len(instance.patches) > 0):
                continue
            for item in instance.patches:
                if isinstance(item, list):
                    results.extend(jsonpatch.JsonPatch(item))
                else:
                    results.extend(item)

            currdict = instance.resp.dict
            itemholder = list()
            for mainitem in results:
                item = copy.deepcopy(mainitem)

                if iloversion:
                    _, bsmodel = self.get_model(currdict, attrreg)
                    if bsmodel:
                        prop = item["path"][1:].split("/")[-1]
                        validator = bsmodel.get_validator(prop)
                        if validator:
                            if isinstance(validator, redfish.ris.validation.PasswordValidator):
                                item["value"] = "******"

                itemholder.append(item)
            if itemholder:
                finalresults.append({instance.maj_type + "(" + instance.path + ")": itemholder})

        return finalresults

    def commit(self):
        """Applies all pending json patches to the server.

        :yields: Two strings.

                1. Path being PATCHed
                2. True if an error occurred during the PATCH, False if no error.
        """
        # Protect iLO Network Interface changes.
        instances = [
            inst for inst in self.monolith.iter() if inst.patches and "Managers/1/EthernetInterfaces/1" not in inst.path
        ]

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if validate_headers(instance, verbose=self.verbose):
                continue

            currdict = dict()
            oridict = instance.resp.dict
            totpayload = dict()
            # apply patches to represent current edits
            for patches in instance.patches:
                if not self._iloversion:
                    self._iloversion = self.getiloversion()
                if self._iloversion < 5.130:
                    self._checkforetagchange(instance=instance)
                fulldict = jsonpatch.apply_patch(oridict, patches)
                for patch in patches:
                    currdict = copy.deepcopy(fulldict)
                    patchpath = patch["path"]
                    pobj = jsonpointer.JsonPointer(patchpath)
                    indpayloadcount = 0
                    for item in pobj.parts:
                        payload = pobj.walk(currdict, item)
                        indpayloadcount = indpayloadcount + 1
                        if isinstance(payload, list):
                            break
                        else:
                            if not isinstance(payload, dict):
                                break
                            currdict = copy.deepcopy(payload)
                    indices = pobj.parts[:indpayloadcount]
                    createdict = lambda x, y: {x: y}
                    while len(indices):
                        payload = createdict(indices.pop(), payload)
                    merge_dict(totpayload, payload)
                currdict = copy.deepcopy(totpayload)
            if "PersistentBootConfigOrder" in currdict and type(currdict) is dict:
                refdict = list(set(currdict["PersistentBootConfigOrder"]))
                items = list(currdict["PersistentBootConfigOrder"])
                items_to_keep = items[: int(len(refdict))]
                currdict = {"PersistentBootConfigOrder": items_to_keep}
            if currdict:
                yield instance.resp.request.path

                put_path = instance.resp.request.path
                etag = self.monolith.paths[put_path].etag
                headers = dict([("If-Match", etag)]) if self._iloversion > 5.130 else None
                for key, value in currdict.items():
                    if key == "OldAdminPassword" and (value != ""):
                        if (value == "null") or (value == "none") or (value == "None"):
                            currdict["OldAdminPassword"] = ""
                        else:
                            hash = hashlib.sha256(value.encode()).hexdigest().upper()
                            headers = dict([("X-HPRESTFULAPI-AuthToken", hash)])
                    elif key == "AdminPassword" and (
                        (value is None) or (value == "none") or (value == "None") or (value == "null")
                    ):
                        currdict["AdminPassword"] = ""
                try:
                    self.patch_handler(
                        put_path,
                        currdict,
                        optionalpassword=self.current_client.bios_password,
                        headers=headers,
                    )
                except IloResponseError:
                    yield True  # Failure
                else:
                    yield False  # Success

    def patch_handler(
        self,
        put_path,
        body,
        headers=None,
        silent=False,
        service=False,
        optionalpassword=None,
        noauth=False,
    ):
        """Performs the client HTTP PATCH operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the patch operation on.
        :type put_path: str
        :param body: the body to perform the operation with.
        :type body: dict
        :param headers: Any additional headers to be added to the request.
        :type headers: dict
        :param optionalpassword: The bios password if it is required for the operation.
        :type optionalpassword: str
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object containing response data
        """
        (put_path, body) = self._checkpostpatch(body=body, path=put_path, patch=True)

        if optionalpassword:
            self.current_client.bios_password = optionalpassword

        results = self.current_client.patch(put_path, body=body, headers=headers, noauth=noauth)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results, replace=True)

        # if results and getattr(results, "status", None) and results.status == 412:
        if results and hasattr(results, "status") and results.status == 412:
            self._updatemono(path=put_path, path_refresh=True)

        if not silent and hasattr(self.typepath.defs, "messageregistrytype"):
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                results, dl_reg=service, verbosity=self.verbose
            )

        return results

    def get_handler(
        self,
        get_path,
        sessionid=None,
        silent=False,
        uncache=False,
        headers=None,
        service=False,
        username=None,
        password=None,
        base_url=None,
        noauth=False,
    ):
        """Performs the client HTTP GET operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the get operation on.
        :type put_path: str
        :param uncache: flag to not store the data downloaded into monolith.
        :type uncache: bool
        :param headers: Any additional headers to be added to the request.
        :type headers: dict
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object
        """
        try:
            results = self.current_client.get(get_path, headers=headers, noauth=noauth)
        except UndefinedClientError:
            if sessionid:
                self.redfishinst = RestClient(
                    sessionid=sessionid,
                    username=username,
                    password=password,
                    base_url=base_url,
                    noauth=noauth,
                )
                if not headers:
                    headers = dict()
                headers["X-Auth-Token"] = sessionid
                results = self.current_client.get(get_path, headers=headers)

        if results and getattr(results, "status", None) and results.status == 404:
            if not silent:
                if hasattr(self.typepath.defs, "messageregistrytype"):
                    ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                        results, dl_reg=service, verbosity=self.verbose
                    )
                else:
                    print_handler("[" + str(results.status) + "]" + " The operation completed successfully.\n")
            return results

        if results and results.status == 200 and sessionid:
            if not silent:
                if hasattr(self.typepath.defs, "messageregistrytype"):
                    ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                        results, dl_reg=service, verbosity=self.verbose
                    )
                else:
                    print_handler("[" + str(results.status) + "]" + " The operation completed successfully.\n")
            return results

        if not uncache and results.status == 200 and not sessionid:
            if self.monolith:
                self.monolith.update_member(resp=results, path=get_path, init=False)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        if not silent:
            if hasattr(self.typepath.defs, "messageregistrytype"):
                ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                    results, dl_reg=service, verbosity=self.verbose
                )
            else:
                print_handler("[" + str(results.status) + "]" + " The operation completed successfully.\n")

        return results

    def post_handler(self, put_path, body, headers=None, silent=False, service=False, noauth=False):
        """Performs the client HTTP POST operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the post operation on.
        :type put_path: str
        :param body: the body to perform the operation with.
        :type body: dict
        :param headers: Any additional headers to be added to the request.
        :type headers: dict
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object containing response data
        """
        (put_path, body) = self._checkpostpatch(body=body, path=put_path)

        results = self.current_client.post(put_path, body=body, headers=headers, noauth=noauth)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results)

        if results.status == 400 and results.dict is None:
            return results
        if not silent and hasattr(self.typepath.defs, "messageregistrytype"):
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                results, dl_reg=service, verbosity=self.verbose
            )

        return results

    def put_handler(
        self,
        put_path,
        body,
        headers=None,
        silent=False,
        optionalpassword=None,
        service=False,
        noauth=False
    ):
        """Performs the client HTTP PUT operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the put operation on.
        :type put_path: str
        :param body: the body to perform the operation with.
        :type body: dict
        :param headers: Any additional headers to be added to the request.
        :type headers: dict
        :param optionalpassword: The bios password if it is required for the operation.
        :type optionalpassword: str
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object containing response data
        """
        if optionalpassword:
            self.current_client.bios_password = optionalpassword
        results = self.current_client.put(put_path, body=body, headers=headers, noauth=noauth)
        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results, replace=True)

        if not silent and hasattr(self.typepath.defs, "messageregistrytype"):
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                results, dl_reg=service, verbosity=self.verbose
            )

        return results

    def delete_handler(self, put_path, headers=None, silent=False, service=False):
        """Performs the client HTTP DELETE operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the delete operation on.
        :type put_path: str
        :param headers: Any additional headers to be added to the request.
        :type headers: dict
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object containing response data
        """
        results = self.current_client.delete(put_path, headers=headers)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        self._modifiedpath(results, delete=True)

        if not silent and hasattr(self.typepath.defs, "messageregistrytype"):
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                results, dl_reg=service, verbosity=self.verbose
            )

        return results

    def head_handler(self, put_path, silent=False, service=False):
        """Performs the client HTTP HEAD operation with monolith and response handling support.
        Response handling will output to logger or string depending on showmessages app argument.

        :param put_path: The REST path to perform the head operation on.
        :type put_path: str
        :param silent: If False response will be parsed based on service flag and output to a log or
                       stdout. If True response will not be parsed and no message output or error
                       messages raised from the response handler.
        :type silent: bool
        :param service: When handling the response, if True registries will be gathered and a full,
                        response will be output if False they will not and response handler will
                        instead return a generic message.
        :type service: bool
        :returns: A :class:`redfish.rest.containers.RestResponse` object containing response data
        """
        results = self.current_client.head(put_path)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        if not silent and hasattr(self.typepath.defs, "messageregistrytype"):
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).output_resp(
                results, dl_reg=service, verbosity=self.verbose
            )

        return results

    def removereadonlyprops(self, currdict, emptyraise=False, removeunique=True, specify_props=None):
        """Remove read only properties from a dictionary. Requires schemas to be available.

        :param currdict: The dictionary to remove read only properties from.
        :type currdict: dictionary
        :param emptyraise: Flag to raise an empty error for handling and failure to parse.
        :type emptyraise: boolean
        :type removeunique: Flag to remove system unique values as well as read only.
        :type removeunique: boolean
        :parm specify_props: Optionally set list of properties to be removed instead of the default.
        :type specify_props: list
        """
        try:
            type_str = self.typepath.defs.typestring
            currtype = currdict.get(type_str, None)
            oridict = copy.deepcopy(currdict)
            if specify_props:
                templist = specify_props
            else:
                templist = [
                    "Modified",
                    "Type",
                    "Description",
                    "Status",
                    "links",
                    "SettingsResult",
                    "Attributes",
                    "@odata.context",
                    "@odata.type",
                    "@odata.id",
                    "@odata.etag",
                    "Links",
                    "Actions",
                    "AvailableActions",
                    "BiosVersion",
                    "AddressOrigin",
                ]
            # Attributes removed and readded later as a validation workaround
            currdict = iterateandclear(currdict, templist)
            iloversion = self.getiloversion()
            if not iloversion:
                return currdict
            self.validationmanager.validatedict(
                currdict,
                currtype=currtype,
                monolith=self.monolith,
                unique=removeunique,
                searchtype=None,
            )
            if oridict.get("Attributes", None):
                currdict["Attributes"] = oridict["Attributes"]
            return currdict
        except:
            if emptyraise is True:
                raise EmptyRaiseForEAFP()
            elif emptyraise == "pass":
                pass
            else:
                raise

    def getidbytype(self, tpe):
        """Return a list of URIs that correspond to the supplied type string.

        :param tpe: type string to search for.
        :type tpe: string.
        """
        urls = list()
        val = next(self.monolith.gettypename(tpe), None)
        urls.extend(self.monolith.typesadded[val] if val else [])
        return urls

    def getcollectionmembers(self, path, fullresp=False):
        """Returns collection/item lists of the provided path.

        :param path: path to return.
        :type path: string.
        :param fullresp: Return full json data instead of only members.
        :type path: bool.
        :returns: list of collection members
        """
        if (
            self.typepath.defs.isgen10
            and hasattr(self.typepath, "gencompany")
            and self.typepath.gencompany
            and "?$expand=." not in path
        ):
            path += "?$expand=." if path.endswith("/") else "/?$expand=."

        members = self.get_handler(path, service=True, silent=True)
        if members and not fullresp:
            try:
                members = members.dict["Members"] if self.typepath.defs.isgen10 else members.dict["Current"]
            except KeyError:
                members = members
        elif fullresp:
            members = [members.dict]

        return members

    def getbiosfamilyandversion(self):
        """Function that returns the current BIOS version information."""
        self._updatemono(currtype="ComputerSystem.", crawl=False)

        try:
            for inst in self.monolith.iter("ComputerSystem."):
                if "Current" in inst.resp.obj["Bios"]:
                    oemjson = inst.resp.obj["Bios"]["Current"]
                    parts = oemjson["VersionString"].split(" ")
                    return parts[0], parts[1][1:]
                else:
                    parts = inst.resp.obj["BiosVersion"].split(" ")
                    return parts[0], parts[1][1:]
        except Exception:
            pass

        return None, None

    def getiloversion(self, skipschemas=False):
        """Function that returns the current iLO version.

        :param skipschemas: flag to determine whether to skip schema download. If False, this will
                            also verify if schemas are available.
        :type skipschemas: bool
        :returns: returns current iLO version
        """
        iloversion = self._iloversion = self._iloversion if self._iloversion else self.typepath.iloversion

        if not iloversion and hasattr(self.redfishinst, "iloversion"):
            iloversion = self._iloversion = self.typepath.iloversion = self.redfishinst.iloversion

        if (
            hasattr(self.typepath, "gencompany")
            and self.typepath.gencompany
            and not self._iloversion
            and not self.typepath.noschemas
        ):
            self.monolith.load(self.typepath.defs.managerpath, crawl=False)
            results = next(iter(self.getprops("Manager.", ["FirmwareVersion", "Firmware"])))

            def quickdrill(_dict, key):
                """function to find key in nested dictionary"""
                return _dict[key]

            while isinstance(results, dict):
                results = quickdrill(results, next(iter(results.keys())))
            iloversionlist = results.replace("v", "").replace(".", "").split(" ")
            try:
                iloversion = float(".".join(iloversionlist[1:3]))
            except:
                iloversion = float(iloversionlist[0])


            model = self.getprops("Manager.", ["Model"])
            if model:
                if next(iter(model))["Model"] == "iLO CM":
                    # Assume iLO 4 types in Moonshot
                    iloversion = None

            self._iloversion = iloversion
        elif (
            hasattr(self.typepath, "gencompany") and not self.typepath.gencompany
        ):  # Assume schemas are available somewhere in non-hpe redfish
            self._iloversion = iloversion = 4.210

        conf = None if not skipschemas else True
        if not skipschemas:
            if iloversion and iloversion >= 4.210:
                conf = self._verifyschemasdownloaded(self.monolith)
            elif iloversion and iloversion < 4.210:
                warning_handler("Please upgrade to iLO 4 version 2.1 or above for schema support.")
            else:
                warning_handler("Schema support unavailable on the currently logged in system.")

        return iloversion if iloversion and iloversion >= 4.210 and conf else None

    def get_selection(self, selector=None, setenable=False, path_refresh=False):
        """Gathers instances and optionally the attributeregistry based on selector.

        :param selector: The type selection for the get operation.
        :type selector: str.
        :param setenable: Flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param path_refresh: Flag to reload the selected instances.
        :type path_refresh: boolean.
        :returns: returns a list of selected items
        """
        instances = self._getinstances(selector=selector, path_refresh=path_refresh)
        if setenable:
            attributeregistryfound = getattributeregistry(instances=instances)
            instances = skipnonsettingsinst(instances=instances)
            return instances, attributeregistryfound

        return instances

    def create_save_header(self):
        """Adds save file headers to show what server the data came from.

        :param selector: The type selection for the get save operation.
        :type selector: str.
        :param selectignore: Return the save header even if there isn't a selection to add it to.
        :type selectignore: boolean
        :returns: returns an header ordered dictionary
        """
        instances = OrderedDict()
        monolith = self.monolith

        self._updatemono(currtype="ComputerSystem.", crawl=False)
        self._updatemono(currtype=self.typepath.defs.biostype, crawl=False)
        self._updatemono(currtype="Manager.", crawl=False)

        instances["Comments"] = OrderedDict()
        for instance in monolith.iter("ComputerSystem."):
            if instance.resp.obj.get("Manufacturer"):
                instances["Comments"]["Manufacturer"] = instance.resp.obj["Manufacturer"]
            if instance.resp.obj.get("Model"):
                instances["Comments"]["Model"] = instance.resp.obj["Model"]
            try:
                if instance.resp.obj["Oem"][self.typepath.defs.oemhp]["Bios"]["Current"]:
                    oemjson = instance.resp.obj["Oem"][self.typepath.defs.oemhp]["Bios"]["Current"]
                    instances["Comments"]["BIOSFamily"] = oemjson["Family"]
                    instances["Comments"]["BIOSDate"] = oemjson["Date"]
            except KeyError:
                pass
        for instance in monolith.iter(self.typepath.defs.biostype):
            try:
                if getattr(instance.resp.obj, "Attributes", False):
                    if instance.resp.obj["Attributes"].get("SerialNumber"):
                        instances["Comments"]["SerialNumber"] = instance.resp.obj["Attributes"]["SerialNumber"]
                if instance.resp.obj.get("SerialNumber"):
                    instances["Comments"]["SerialNumber"] = instance.resp.obj["SerialNumber"]
            except KeyError:
                pass
        for instance in monolith.iter("Manager."):
            if instance.resp.obj.get("FirmwareVersion"):
                instances["Comments"]["iLOVersion"] = instance.resp.obj["FirmwareVersion"]

        return instances

    def download_path(self, paths, crawl=True, path_refresh=False):
        """Loads paths into the monolith.

        :param paths: list of paths to download
        :type paths: list
        :param path_refresh: Flag to reload the paths or not.
        :type path_refresh: bool.
        :param crawl: Flag to determine if load should traverse found links.
        :type crawl: boolean.
        """
        if not paths:
            return
        try:
            list(
                map(
                    lambda x: self.monolith.load(
                        path=x,
                        init=False,
                        path_refresh=path_refresh,
                        crawl=crawl,
                        includelogs=True,
                    ),
                    paths,
                )
            )
        except Exception as excp:
            try:
                if excp.errno == 10053:
                    raise SessionExpired()
            except:
                raise excp
            else:
                raise excp

    def get_model(self, currdict, attributeregistry, latestschema=None, newarg=None, proppath=None):
        """Returns a model and possibly a bios model for the current instance's schema/registry.
        This model can be used to read schema data and validate patches.

        :param currdict: The dictionary to gather the schema model from.
        :type currdict: dict
        :param attributeregistry: The current systems attribute registry. If not gathering a bios
                                  registry this can be set to None.
        :type attributeregistry: dict
        :param latestschema: Flag to determine if we should drop the schema version when we try to
                             match schema information. If True, the version will be dropped.
        :type latestschema: bool
        :param newargs: List of multi level properties to be gathered.
        :type newargs: list
        :param proppath: The path of the schema you want to validate (from Location header).
        :type proppath: str
        :returns: model and bios model
        """
        type_str = self.typepath.defs.typestring
        bsmodel = None
        valobj = self.validationmanager
        model = valobj.get_registry_model(
            currtype=currdict[type_str],
            newarg=newarg,
            latestschema=latestschema,
            proppath=proppath,
        )
        if not attributeregistry and model:
            return model, bsmodel
        if not model and not attributeregistry:
            LOGGER.warning("Unable to locate registry/schema for %s\n", currdict[type_str])
            return None, None
        attrval = currdict.get("AttributeRegistry", None)
        attrval = list(attributeregistry.values())[0] if not attrval and attributeregistry else attrval
        bsmodel = valobj.get_registry_model(
            currtype=attrval if attrval else currdict[type_str],
            newarg=newarg,
            latestschema=latestschema,
            searchtype=self.typepath.defs.attributeregtype,
        )
        return model, bsmodel

    def _build_monolith(self, path=None, includelogs=False, skipbuild=False, json_out=False):
        """Run through the RIS tree to build monolith

        :param path: path to initiate login to.
        :type path: str.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.
        :param skipbuild: if true, skip build of monolith (initialize empty)
        :type skipbuild: True
        """
        self.monolith = RisMonolith(self.current_client, self.typepath)
        if not skipbuild:
            self.monolith.load(path=path, includelogs=includelogs, init=True, json_out=json_out)
        else:
            self.monolith.update_member(
                resp=self.current_client.root,
                path=self.current_client.default_prefix,
                init=False,
            )

    def _modifiedpath(self, results, delete=False, replace=False):
        """Check the path and set the modified flag

        :param delete: Flag to delete the path in the results
        :type delete: bool
        :param replace: Flag to replace the path from the results
        :type replace: bool
        :param results: Response for the path
        :type results: RestResponse
        """
        if not results or results.status not in (200, 201):
            return
        path = results.path
        path = path.split("/Actions")[0] if "Actions" in path else path
        path = path + "/" if self.typepath.defs.isgen10 and path[-1] != "/" else path
        if not replace and path in self.monolith.paths:
            self.monolith.paths[path].modified = True
            _ = self.monolith.markmodified(path)
        if delete and path in self.monolith.paths:
            self.monolith.removepath(path)
        if replace and path in self.monolith.paths:
            self.monolith.paths[path].modified = True
            self.monolith.paths[path].patches = []

    def _checkforchange(self, paths, crawl=True):
        """Check if the given paths have been modified and updates monolith if it has

        :param paths: paths to be checked
        :type paths: list
        """
        (pathtoetag, _) = self._gettypeswithetag()
        mono = self.monolith
        self.download_path(list(paths), crawl=crawl, path_refresh=True)
        etags = [None if path not in mono.paths else mono.paths[path].etag for path in paths]
        sametag = [
            path
            for ind, path in enumerate(paths)
            if path in pathtoetag and path in self.monolith.paths and pathtoetag[path] != etags[ind]
        ]
        for path in sametag:
            self.monolith.paths[path].patches = []
        if sametag:
            LOGGER.warning(
                "The data in the following paths have been updated. " "Recheck the changes made to . %s",
                ",".join([str(path) for path in sametag]),
            )

    def _updatemono(self, currtype=None, path=None, crawl=False, path_refresh=False):
        """Check if type/path exists in current monolith

        :param entrytype: the found entry type.
        :type entrytype: str.
        :param currtype: the current entry type.
        :type currtype: str.
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: boolean.
        """
        monolith = self.monolith
        currtype = None if currtype == '"*"' else currtype
        paths = set()
        if currtype:
            for path, resp in monolith.paths.items():
                if currtype and currtype.lower() not in resp.maj_type.lower():
                    continue
                if path_refresh or not resp:
                    paths.add(path)
                if resp:
                    try:
                        if not resp.dict:
                            raise AttributeError
                    except AttributeError:
                        paths.add(path)
                if resp.modified:
                    paths.add(path)
                    paths.update(monolith.checkmodified(path) if path in monolith.ctree else set())
        elif path:
            if monolith.paths and not list(monolith.paths)[0][-1] == "/":
                path = path[:-1] if path[-1] == "/" else path
            if path_refresh or not monolith.path(path):
                paths.add(path)
            if path in monolith.paths and monolith.paths[path].modified:
                paths.add(path)
                paths.update(monolith.checkmodified(path) if path in monolith.ctree else set())
        if paths:
            self._checkforchange(list(paths), crawl=crawl)

    def _verifyschemasdownloaded(self, monolith):
        """Function to verify that the schema has been downloaded

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        """

        schemaid = self.typepath.schemapath
        regid = self.typepath.regpath

        if not (schemaid and regid):
            warning_handler("Missing Schemas or registries.")
            return None

        schemacoll = next(monolith.gettypename(self.typepath.defs.schemafilecollectiontype), None)
        if not schemacoll or any(
            paths.lower() == schemaid and monolith.paths[paths] for paths in monolith.typesadded[schemacoll]
        ):
            self.download_path([schemaid], crawl=False)
            schemacoll = next(monolith.gettypename(self.typepath.defs.schemafilecollectiontype), None)

        regcoll = next(monolith.gettypename(self.typepath.defs.regfilecollectiontype), None)
        if not regcoll or any(
            paths.lower() == regid and monolith.paths[paths] for paths in monolith.typesadded[regcoll]
        ):
            self.download_path([regid], crawl=False)
            regcoll = next(monolith.gettypename(self.typepath.defs.regfilecollectiontype), None)

        return any(
            paths.lower() in (schemaid.lower(), regid.lower()) and monolith.paths[paths] for paths in monolith.paths
        )

    def _validatechanges(
        self,
        instance=None,
        attributeregistry=None,
        latestschema=None,
        proppath=None,
        newdict=None,
        oridict=None,
        unique=False,
    ):
        """Validate the changes that are requested by the user.

        :param newdict: dictionary with only the properties that have changed
        :type newdict: dict.
        :param oridict: selection dictionary with current state.
        :type oridict: dict.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param iloversion: current iLO version.
        :type iloversion: float.
        :param instance: current selection instance.
        :type instance: RisMonolithMemberv100.
        :param attrreg: Registry entry of the given attribute.
        :type attrreg: RepoRegistryEntry.
        """
        entrymono = self.monolith
        currtype = oridict[self.typepath.defs.typestring]
        validation_manager = self.validationmanager
        errors, warnings = validation_manager.validatedict(
            newdict,
            currtype=attributeregistry[instance.maj_type] if attributeregistry else currtype,
            monolith=entrymono,
            unique=unique,
            searchtype=self.typepath.defs.attributeregtype if attributeregistry else None,
            latestschema=latestschema,
            proppath=proppath,
        )

        validation_errors = errors
        for warninngs in warnings:
            warning_handler(warninngs, override=True)
        if validation_errors and len(validation_errors) > 0:
            raise ValidationError(validation_errors)
        checkallowablevalues(newdict=newdict, oridict=oridict)

    def _getinstances(self, selector=None, path_refresh=False, crawl=False):
        """Main function to get instances of particular type and reload

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param path_refresh: flag to reload the selected instances.
        :type path_refresh: boolean.
        :returns: returns a list of selected items
        """
        instances = list()
        selector = self.selector if not selector else selector
        if selector:
            selector = ".".join(selector.split("#")[-1].split(".")[:2])
            if self.monolith:
                self._updatemono(currtype=selector, crawl=crawl, path_refresh=path_refresh)
        if not selector:
            return instances
        selector = None if selector == '"*"' else selector
        if self.monolith:
            if self.redfishinst.is_redfish:
                instances = [
                    inst
                    for inst in self.monolith.iter(selector)
                    if inst.maj_type not in ["object", "string"] and "redfish" in inst.path
                ]
            else:
                instances = [
                    inst
                    for inst in self.monolith.iter(selector)
                    if inst.maj_type not in ["object", "string"] and "rest" in inst.path
                ]

        _ = [setattr(inst, "patches", []) for inst in instances if path_refresh]
        return instances

    def _checkpostpatch(self, body=None, path=None, patch=False):
        """Make the post file compatible with the system generation

        :param body: contents to be checked
        :type body: str.
        :param path: The URL location to check
        :type path: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :param url: originating url.
        :type url: str.
        :param sessionid: session id to be used instead of iLO credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param iloresponse: flag to return the iLO response.
        :type iloresponse: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param patch: flag to determine if a patch is being made
        :type patch: boolean.
        :returns: modified body and path parameter for target and action respectively
        """
        try:
            if self.typepath.defs.flagforrest:
                if "Target" not in body and not patch:
                    if "/Oem/Hp" in path:
                        body["Target"] = self.typepath.defs.oempath

                if path.startswith("/redfish/v1"):
                    path = path.replace("/redfish", "/rest", 1)

                if "/Actions/" in path:
                    ind = path.find("/Actions/")
                    path = path[:ind]

                if path.endswith("/"):
                    path = path[:-1]
            elif path.startswith("/rest/") and self.typepath.defs.isgen9:
                results = self.get_handler(put_path=path, service=True, silent=True)
                if results and results.status == 200:
                    if results.dict:
                        if "Target" in body:
                            actions = results.dict["Oem"][self.typepath.defs.oemhp]["Actions"]
                        elif "Actions" in body:
                            actions = results.dict["Actions"]
                        else:
                            return path, body

                    allkeys = list(actions.keys())
                    targetkey = [x for x in allkeys if x.endswith(body["Action"])]

                    if targetkey[0].startswith("#"):
                        targetkey[0] = targetkey[0][1:]

                path = path.replace("/rest", "/redfish", 1)
                path = path + "/Actions"

                if "Target" in body:
                    path = path + self.typepath.defs.oempath
                    del body["Target"]

                if targetkey:
                    path = path + "/" + targetkey[0] + "/"

            return path, body
        except Exception as excp:
            raise excp

    def _checkforetagchange(self, instance=None):
        """Function to check the status of the etag

        :param instance: retrieved instance to check etag for change.
        :type instance: dict.
        """
        if instance:
            path = instance.path
            (oldtag, _) = self._gettypeswithetag()
            self._updatemono(path=path, path_refresh=True)
            (newtag, _) = self._gettypeswithetag()
            if (oldtag[path] != newtag[path]) and self.typepath.defs.hpilodatetimetype not in instance.maj_type:
                warning_handler(
                    "The property you are trying to change "
                    "has been updated. Please check entry again "
                    " before manipulating it.\n"
                )
                raise ValueChangedError()

    def _gettypeswithetag(self):
        """Gathers etags of all paths in monolith and their type associations"""
        instancepath = dict()
        instances = dict()

        for inst in self.monolith.iter():
            instancepath[inst.path] = inst.maj_type
            instances[inst.path] = inst.etag

        return [instances, instancepath]

    # VNIC Functions
    def generate_save_token(self, app_obj):
        return app_obj.generate_and_save_apptoken()

    def delete_token(self, app_obj):
        return app_obj.remove_apptoken()

    def token_exists(self, app_obj):
        return app_obj.apptoken_exists()

    def vnic_login(
            self,
            app_obj=None,
            path=None,
            skipbuild=False,
            includelogs=False,
            json_out=False,
            base_url=None,
            username=None,
            password=None,
            log_dir=None,
            login_otp=None,
            is_redfish=False,
            proxy=None,
            user_ca_cert_data=None,
            biospassword=None,
            sessionid=None,
    ):
        # Calling libhpsrv function to get session token
        session_location = ""
        if sessionid:
            session_key = sessionid
        else:
            session_key, session_location = app_obj.vlogin()

        if not session_key or not session_location:
            raise Exception("Empty Session Id or Session Location was returned.\n")

        self.login(
            username=username,
            password=password,
            sessionid=session_key,
            base_url=base_url,
            path=path,
            skipbuild=skipbuild,
            includelogs=includelogs,
            biospassword=biospassword,
            is_redfish=is_redfish,
            proxy=proxy,
            user_ca_cert_data=user_ca_cert_data,
            json_out=json_out,
            login_otp=login_otp,
            log_dir=log_dir,
            session_location=session_location,
        )

    def vexists(self, app_obj):
        # app_obj = Appaccount()
        return app_obj.vnic_exists()

    def getilover_beforelogin(self, app_obj):
        # app_obj = Appaccount(appname=appname, appid=appid, username=username, password=password)
        ilo_ver, securitystate = app_obj.version_beforelogin()
        return ilo_ver, securitystate

    def GetIPAddress(self):
        app_obj = AppAccount()
        IPAddr = app_obj.GetIPAddress()
        if "https://" not in IPAddr:
            IPAddr = "https://" + IPAddr
        return IPAddr

    def ListAppIds(self, app_obj):
        appid_list_info = app_obj.CompareAppIds()
        return appid_list_info

    def ExpandAppId(self, app_obj, appid):
        expand_app_id = app_obj.ExpandAppId(appid)
        return expand_app_id
