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
"""Utility functions for internal and external use. Contains general json navigating functions as
well as some monolith utility functions."""
import copy
import logging
import re
import sys

import six

if six.PY3:
    from functools import reduce

try:
    from collections import Mapping
except ImportError:
    from collections.abc import Mapping

import jsonpath_rw
from six import iterkeys, string_types

from redfish.ris.rmc_helper import IncorrectPropValue

try:
    # itertools ifilter compatibility for python 2
    from future_builtins import filter
except ImportError:
    # filter function provides the same functionality in python 3
    pass

# ---------Debug logger---------

LOGGER = logging.getLogger()


# ---------End of debug logger---------


def print_handler(msg):
    """Helper function for handling warning messages appropriately. If LOGGER level is set to 40
    print out the warnings, else log them as a warning.

    :param msg: The warning message.
    :type msg: str
    """
    # if override:
    sys.stdout.write(msg)
    # else:
    # if LOGGER.getEffectiveLevel() == 40:
    # LOGGER.warning(msg)


def warning_handler(msg, override=False):
    """Helper function for handling warning messages appropriately. If LOGGER level is set to 40
    print out the warnings, else log them as a warning.

    :param msg: The warning message.
    :type msg: str
    """
    # if override:
    # sys.stdout.write(msg)
    # else:
    # if LOGGER.getEffectiveLevel() == 40:
    LOGGER.warning(msg)


def validate_headers(instance, verbose=False):
    """Validates an instance is patchable.

    :param instance: Instance of the property to check.
    :type instance: :class:`redfish.ris.RisMonolithMemberv100`
    :param verbose: Flag to print or log more information.
    :type verbose: bool
    :returns: True if the setting is not patchable, False if it is.
    """
    skip = False
    try:
        headervals = instance.resp.getheaders()
        for kii, val in headervals.items():
            if kii.lower() == "allow":
                if "PATCH" not in val:
                    if verbose:
                        warning_handler("Skipping read-only path: %s\n" % instance.resp.request.path)
                    skip = True
    except:
        pass
    return skip


def merge_dict(currdict, newdict):
    """Merges dictionaries together.

    :param currdict: Dictionary that will absorb the second.
    :type currdict: dict
    :param newdict: Dictionary to merge into the first.
    :type newdict: dict
    """
    for k, itemv2 in list(newdict.items()):
        itemv1 = currdict.get(k)

        if isinstance(itemv1, Mapping) and isinstance(itemv2, Mapping):
            merge_dict(itemv1, itemv2)
        elif isinstance(itemv1, list) and isinstance(itemv2, list):
            j = 0
            for i in itemv2:
                if isinstance(i, dict):
                    for k, v in i.items():
                        if k not in [d.keys() for d in itemv1]:
                            itemv1[j][k] = v
                            j = j + 1
                else:
                    itemv1.append(i)
        else:
            currdict[k] = itemv2


def get_errmsg_type(results):
    """Return the registry type of a response.

    :param results: rest response.
    :type results: :class:`redfish.rest.containers.RestResponse`
    :returns: A Registry Id type string, None if not match is found, or no_id if the
              response is not an error message
    :rtype: None or string
    """

    message_type = None
    try:
        jsonpath_expr = jsonpath_rw.parse("$..MessageId")
        messageid = [match.value for match in jsonpath_expr.find(results.dict)]
        if not messageid:
            jsonpath_expr = jsonpath_rw.parse("$..MessageID")
            messageid = [match.value for match in jsonpath_expr.find(results.dict)]
        if messageid:
            message_type = messageid[0].split(".")[0]
    except:
        pass

    return message_type


def filter_output(output, sel, val):
    """Filters a list of dictionaries based on a key:value pair only returning the dictionaries
    that include the key and value.

    :param output: List of dictionaries to check for the key:value.
    :type output: list
    :param sel: the key for the property to be filtered by.
    :type sel: str
    :param val: value for the property be filtered by.
    :type val: str
    :returns: A filtered list from output parameter
    :rtype: list
    """
    # TODO: check if this can be replaced by navigatejson
    newoutput = []
    if isinstance(output, list):
        for entry in output:
            if isinstance(entry, dict):
                if "/" in sel:
                    sellist = sel.split("/")
                    newentry = copy.copy(entry)

                    for item in sellist:
                        if item in list(newentry.keys()):
                            if item == sellist[-1] and str(newentry[item]) == str(val):
                                newoutput.append(entry)
                            else:
                                newentry = newentry[item]
                else:
                    if sel in list(entry.keys()) and entry[sel] == val:
                        newoutput.append(entry)
            else:
                return output

    return newoutput


def checkallowablevalues(newdict=None, oridict=None):
    """Validate dictionary changes with Redfish allowable values. This will raise an
    :class:`redfish.ris.rmc_helper.IncorrectPropValue` error if the dictionary is not valid.

    :param newdict: dictionary with only the properties that have changed.
    :type newdict: dict
    :param oridict: Full dictionary with current state. (Includes @Redfish.AllowableValues)
    :type oridict: dict
    """
    for strmatch in re.finditer("@Redfish.AllowableValues", str(oridict)):
        propname = str(oridict)[: strmatch.start()].split("'")[-1]
        strtomatch = "$..'{0}@Redfish.AllowableValues'".format(propname)
        jsonpath_expr = jsonpath_rw.parse(strtomatch)
        matches = jsonpath_expr.find(oridict)
        if matches:
            for match in matches:
                fullpath = str(match.full_path)
                if "Actions" in fullpath:
                    continue
                checkpath = fullpath.split("@Redfish.AllowableValues")[0]
                jexpr2 = jsonpath_rw.parse(checkpath)
                valmatches = jexpr2.find(newdict)
                if valmatches:
                    for mat in valmatches:
                        res = [val for val in match.value if mat.value.lower() == val.lower()]
                        if not res:
                            raise IncorrectPropValue(
                                "Incorrect Value "
                                "entered. Please enter one of the below "
                                "values for {0}:\n{1}".format("/".join(checkpath.split(".")), str(match.value)[1:-1])
                            )


def navigatejson(selector, currdict, val=None):
    """Function for navigating the json dictionary. Searches a dictionary for specific keys
    and possibly values, returning only the dictionary sections for the requested keys and values.

    :param selector: the property required from current dictionary.
    :type selector: list
    :param val: value to be filtered by.
    :type val: str or int or bool
    :param currdict: json dictionary of list to be filtered
    :type currdict: json dictionary/list
    :returns: returns a dictionary of selected items
    """
    # TODO: Check for val of different types(bool, int, etc)
    temp_dict = dict()
    createdict = lambda y, x: {x: y}
    getkey = lambda cdict, sel: next((item for item in iterkeys(cdict) if sel.lower() == item.lower()), sel)
    getval = lambda cdict, sele: [cdict[sel] if sel in cdict else "~!@#$%^&*)()" for sel in [getkey(cdict, sele)]][0]
    fullbreak = False
    seldict = copy.deepcopy(currdict)
    for ind, sel in enumerate(selector):
        if isinstance(seldict, dict):
            selector[ind] = getkey(seldict, sel)
            seldict = getval(seldict, sel)
            if seldict == "~!@#$%^&*)()":
                return None
            if val and ind == len(selector) - 1:
                cval = ",".join(seldict) if isinstance(seldict, (list, tuple)) else seldict
                if not (
                    (val[-1] == "*" and str(cval).lower().startswith(val[:-1].lower()))
                    or str(cval).lower() == val.lower()
                ):
                    fullbreak = True
        elif isinstance(seldict, (list, tuple)):
            returndict = []
            for items in seldict:
                correctcase = selector[ind:]
                returnseldict = navigatejson(correctcase, items)
                selector[ind:] = correctcase
                if returnseldict is not None:
                    returndict.append(returnseldict)
            if returndict:
                seldict = returndict
            else:
                fullbreak = True
            if seldict:
                seldict = {selector[ind - 1]: seldict}
                selsdict = reduce(createdict, [seldict] + selector[: ind - 1][::-1])
                merge_dict(temp_dict, selsdict)
                return temp_dict
            else:
                break
        else:
            fullbreak = True
            break
    if fullbreak:
        return None
    else:
        selsdict = reduce(createdict, [seldict] + selector[::-1])
        merge_dict(temp_dict, selsdict)
    return temp_dict


def iterateandclear(dictbody, proplist):
    """Iterate over a dictionary and remove listed properties.

    :param dictbody: json body
    :type dictbody: dict or list
    :param proplist: property list
    :type proplist: list
    """
    if isinstance(dictbody, dict):
        _ = [dictbody.pop(key) for key in proplist if key in dictbody]
        for key in dictbody:
            dictbody[key] = iterateandclear(dictbody[key], proplist)
    if isinstance(dictbody, list):
        for ind, val in enumerate(dictbody):
            dictbody[ind] = iterateandclear(val, proplist)
    return dictbody


def skipnonsettingsinst(instances):
    """Removes non /settings sections. Useful for only returning settings monolith members.
    Example: Members with paths `/redfish/v1/systems/1/bios/` and
    `/redfish/v1/systems/1/bios/settings`
    will return only the `/redfish/v1/systems/1/bios/settings` member.

    :param instances: list of :class:`redfish.ris.ris.RisMonolithMemberv100`
      instances to check for settings paths.
    :type instances: list
    :returns: list of :class:`redfish.ris.ris.RisMonolithMemberv100` setting instances
    :rtype: list
    """
    instpaths = [inst.path.lower() for inst in instances]
    cond = list(filter(lambda x: x.endswith(("/settings", "settings/")), instpaths))
    paths = [path.split("settings/")[0].split("/settings")[0] for path in cond]
    newinst = [inst for inst in instances if inst.path.lower() not in paths]
    return newinst


def getattributeregistry(instances, adict=None):
    # add try except return {} after test
    """Gets an attribute registry in given monolith instances.

    :param instances: list of :class:`redfish.ris.ris.RisMonolithMemberv100` instances to be
      checked for attribute registry.
    :type instances: list
    :param adict: A dictionary containing an AttributeRegistry
    :type adict: dict
    :return: returns a dictionary containing the attribute registry string(s)
    :rtype: dict
    """

    if adict:
        return adict.get("AttributeRegistry", None)
    newdict = {}
    for inst in instances:
        try:
            if "AttributeRegistry" in inst.resp.dict:
                if inst.defpath is not None:
                    if not ("bios/settings" in inst.defpath):
                        newdict[inst.maj_type] = inst.resp.obj["AttributeRegistry"]
                        return newdict
                newdict[inst.maj_type] = inst.resp.obj["AttributeRegistry"]
        except AttributeError:
            LOGGER.warning("Invalid/Unpopulated Response: %s\nType:%s\nPath:%s\n" % (inst.resp, inst.type, inst.path))
    return newdict


def diffdict(newdict=None, oridict=None, settingskipped=[False]):
    """Diff two dictionaries, returning only the values that are different between the two.

    :param newdict: The first dictionary to check for differences.
    :type newdict: dict
    :param oridict: The second dictionary to check for differences.
    :type oridict: dict
    :param settingskipped: Flag to determine if any settings were missing.
    :type settingskipped: list
    :returns: dictionary with only the properties that have changed.
    :rtype: dict
    """
    try:
        if newdict == oridict:
            return {}
    except:
        try:
            if set(newdict) == set(oridict):
                return {}
        except:
            pass

    newdictkeys = list(newdict.keys())
    newdictlist = []
    if type(oridict) is list:
        oridict = oridict[0]
        newdictlist.append(newdict)
    oridictkeys = list(oridict.keys())
    newdictkeyslower = [ki.lower() for ki in newdictkeys]
    oridictkeyslower = [ki.lower() for ki in list(oridict.keys())]
    missingkeys = list(set(newdictkeyslower) - set(oridictkeyslower))
    for kis in missingkeys:
        del newdict[newdictkeys[newdictkeyslower.index(kis)]]
        warning_handler("Attribute {0} not found in the selection...".format(kis))
        settingskipped = [True]
    for key, val in list(newdict.items()):
        if key not in oridict:
            keycase = oridictkeys[oridictkeyslower.index(key.lower())]
            del newdict[key]
            key = keycase
            newdict[key] = val
        if isinstance(val, dict):
            res = diffdict(newdict[key], oridict[key])
            if res:
                newdict[key] = res
            else:
                del newdict[key]
        elif isinstance(val, list):
            if val == oridict[key]:
                del newdict[key]
                continue
            if len(val) == 1 and isinstance(val[0], dict):
                if newdict[key] and oridict[key]:
                    res = diffdict(newdict[key][0], oridict[key][0], settingskipped)
                    if res:
                        newdict[key][0] = res
                    else:
                        del newdict[key]
            if [li for li in val if not isinstance(li, string_types)]:
                continue
            else:
                if val:
                    if [va.lower() for va in val] == [va.lower() if va else va for va in oridict[key]]:
                        del newdict[key]
        # TODO: check if lowercase is correct or buggy for string types
        elif isinstance(val, (string_types, int, type(None))):
            if newdict[key] == oridict[key]:
                del newdict[key]
    if not newdictlist:
        return newdict
    else:
        return newdictlist


def json_traversal(data, key_to_find, ret_dict=False):
    """
    PENDING MODIFICATION TO MORE GENERALIZED NOTATION

    Recursive function to traverse a JSON resposne object and retrieve the array of
    relevant data (value or full key/value pair). Only a single key needs to be found within the
    dictionary in order to return a valid dictionary or value.

    #Intended Usage:
    - Error response message parsing
    - Checkreadunique in Validation

    :param data: json data to be parsed
    :type data: JSON error response object
    :param key_to_find: JSON key to be found
    :type key_to_find: String
    :param ret_dict: return dictionary instead of just value
    :type ret_dict: boolean
    :returns: value or dictionary containing 'key_to_find'
                (and all additional keys at the same level).
    """

    try:
        for i, _iter in enumerate(data):
            try:
                if _iter == data:
                    return None
            except Exception:
                pass
            try:
                if key_to_find.lower() == _iter.lower():
                    if ret_dict:
                        return data
                    else:
                        return data[_iter]
            except Exception:
                pass
            try:
                if key_to_find.lower() in [str(_.lower()) for _ in _iter.keys()]:
                    if ret_dict:
                        return data
                    else:
                        return data[_iter]
            except Exception:
                pass
            _tmp = None
            try:
                if isinstance(data[_iter], dict):
                    for k in data[_iter].keys():
                        if k.lower() == key_to_find.lower():
                            if ret_dict:
                                return data[_iter]
                            else:
                                return data[_iter][k]
                    _tmp = json_traversal(data[_iter], key_to_find, ret_dict)
                elif isinstance(data[_iter], list) or isinstance(data[_iter], tuple):
                    try:
                        _tmp = json_traversal(data[i], key_to_find, ret_dict)
                    except Exception:
                        _tmp = json_traversal(data[_iter], key_to_find, ret_dict)
            except Exception:
                _tmp = json_traversal(data[i], key_to_find, ret_dict)
            finally:
                if _tmp:
                    return _tmp
    except Exception:
        pass


def json_traversal_delete_empty(data, old_key=None, _iter=None, remove_list=None):
    """
    Recursive function to traverse a dictionary and delete things which
    match elements in the remove_list

    :param data: to be truncated
    :type data: list or dict
    :param old_key: key from previous recursive call (higher in stack)
    :type old_key: dictionary key
    :param _iter: iterator tracker for list (tracks iteration across
                  recursive calls)
    :type _iter: numerical iterator
    :param remove_list: list of items to be removed
    :type: list
    :returns: none
    """

    if not remove_list:
        remove_list = ["NONE", None, "", {}, [], "::", "0.0.0.0", "Unknown"]
    list_quick_scan = False

    if isinstance(data, list):
        if _iter is None:
            for idx, val in enumerate(data):
                if idx is (len(data) - 1):
                    list_quick_scan = True

                json_traversal_delete_empty(val, old_key, idx, remove_list)

            if list_quick_scan:
                for j in remove_list:
                    for _ in range(data.count(j)):
                        data.remove(j)

    elif isinstance(data, dict):
        delete_list = []
        for key, value in data.items():
            if (
                (isinstance(value, dict) and len(value) < 1)
                or (isinstance(value, list) and len(value) < 1)
                or None
                or value in remove_list
                or key in remove_list
            ):
                delete_list.append(key)

            else:
                json_traversal_delete_empty(value, key, remove_list=remove_list)
                # would be great to not need this section; however,
                # since recursive deletion is not possible, this is needed
                # if you can figure out how to pass by reference then fix me!
                if (isinstance(value, dict) and len(value) < 1) or None or value in remove_list:
                    delete_list.append(key)
        for dl_entry in delete_list:
            try:
                del data[dl_entry]
            except KeyError:
                pass
