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

"""Error response handler for Redfish or LegacryRest responses. Extended information only available
with registries available on system, otherwise will return generic error responses."""
import logging

from redfish.ris.ris import SessionExpired
from redfish.ris.rmc_helper import (
    EmptyRaiseForEAFP,
    IdTokenError,
    IloLicenseError,
    IloResponseError,
    ScepenabledError,
    ValueChangedError,
)
from redfish.ris.utils import (
    get_errmsg_type,
    json_traversal,
    print_handler,
    warning_handler,
)

# ---------Debug logger---------

LOGGER = logging.getLogger()


# ---------End of debug logger---------


class ResponseHandler(object):
    """Class to handle error responses from the server.

    :param validation_mgr: ValidationManager instance to gather registries if needed. Available
                           in an RmcApp class as an attribute.
    :type validation_mgr: ValidationManager
    :param msg_reg_type: Redfish (#MessageRegistry.) or LegacyRest (MessageRegistry.)
                         message registry string. Available in Typesandpathdefines class.
    :type msg_reg_type: str
    """

    def __init__(self, validaition_mgr, msg_type):
        self.validation_mgr = validaition_mgr
        self.msg_reg_type = msg_type

    def output_resp(self, response, dl_reg=False, verbosity=1, stderr_flag=False):
        """Prints or logs parsed MessageId response. Will raise an IloResponseError or return
        a list of message response data which includes the information returned from
        message_handler.

        :param response: message response of a call.
        :type response: :class:`redfish.rest.containers.RestResponse`
        :param dl_reg: Flag to download registry. If this is set to True a generic message response
                       will be returned instead of gathered from registries.
        :type dl_reg: bool
        :param verbosity: Optional verbosity level. Only modifies what is output to log or screen.
        :type verbosity: int
        :returns: List of error response dictionaries.
        """
        retdata = None

        if response.status > 299:
            message_text = "No error message returned or unable to parse error response."
        else:
            message_text = "The operation completed successfully."

        if response.status < 300 and (response._rest_request.method == "GET" or not response.read):
            # for rawget
            if verbosity == 0:
                verbosity = 1
            print_handler(
                self.verbosity_levels(
                    message=message_text, response_status=response.status, verbosity=verbosity, dl_reg=dl_reg
                ),
                stderr_flag,
            )
        elif response.status == 401:
            raise SessionExpired()
        elif response.status == 403:
            results = response.dict["error"]["@Message.ExtendedInfo"]
            for result in results:
                if "License" in list(result.values())[0] or "license" in list(result.values())[0]:
                    raise IloLicenseError("")
            raise IdTokenError()
        elif response.status == 412:
            warning_handler(
                "The property you are trying to change has been updated. "
                "Please check entry again before manipulating it.\n",
                override=True,
            )
            raise ValueChangedError()
        else:
            retdata = self.message_handler(
                response_data=response,
                verbosity=verbosity,
                message_text=message_text,
                dl_reg=dl_reg,
                stderr_flag=stderr_flag,
            )
        if response.status == 400:
            results = response.dict["error"]["@Message.ExtendedInfo"]
            for result in results:
                if "License" in list(result.values())[0] or "license" in list(result.values())[0]:
                    raise IloLicenseError("")
                if "UnsupportedOperationACEEnabled" in list(result.values())[0]:
                    raise ScepenabledError("")
        if response.status > 299:
            raise IloResponseError("")
        else:
            return retdata

    def message_handler(self, response_data, verbosity=0, message_text="No Response", dl_reg=False, stderr_flag=False):
        """Prints or logs parsed MessageId response based on verbosity level and returns the
        following message information in a list:

        * MessageArgs
        * MessageId
        * RestResponse status
        * Resolution
        * Full error message text

        :param response_data: message response of a call.
        :type response_data: :class:`redfish.rest.containers.RestResponse`
        :param verbosity: Optional verbosity level. Only modifies what is output to log or screen.
        :type verbosity: int
        :param message_text: Response message text. If not provided, message_handler will attempt to
                             parse it from the RestResponse and registries.
        :type message_text: str
        :param dl_reg: Flag to download registry. If this is set to True a generic message response
                       will be returned instead of gathered from registries.
        :type dl_reg: bool
        :returns: List of error response dictionaries.
        """
        _tmp_message_id = _tmp_description = _tmp_resolution = message_text
        retlist = list()
        response_error_str = ""
        try:
            response_status = response_data.status
        except (AttributeError, ValueError):
            response_status = "???"
        try:
            response_data = response_data.dict
        except (AttributeError, ValueError):
            pass
        try:
            for inst in self.get_message_data(response_data, dl_reg):
                try:
                    for _key in inst.keys():
                        if "messageid" in str(_key.lower()):
                            _tmp_message_id = inst[_key]
                        if "description" in str(_key.lower()):
                            _tmp_description = inst[_key]
                    if inst.get("Message") and inst.get("MessageArgs"):
                        for i in range(inst["Message"].count("%")):
                            inst["Message"] = inst["Message"].replace(
                                "%" + str(i + 1), '"' + inst["MessageArgs"][i] + '"'
                            )
                        message_text = inst.get("Message", " ")
                    elif inst.get("Message"):
                        message_text = inst.get("Message", " ")
                    elif response_status not in [200, 201]:
                        message_text = _tmp_message_id
                    _tmp_resolution = inst.get("Resolution", " ")
                except (KeyError, ValueError, TypeError):
                    pass
                finally:
                    response_error_str += "[%s] %s\n" % (response_status, message_text)
                    print_handler(
                        self.verbosity_levels(
                            message_text,
                            _tmp_message_id,
                            _tmp_description,
                            _tmp_resolution,
                            response_status,
                            verbosity,
                            dl_reg,
                        ),
                        stderr_flag,
                    )
                    retlist.append(inst)
        except Exception:
            if not message_text:
                message_text = _tmp_message_id
            response_error_str += "[%s] %s\n" % (response_status, message_text)
            print_handler(
                self.verbosity_levels(
                    message_text,
                    _tmp_message_id,
                    _tmp_description,
                    _tmp_resolution,
                    response_status,
                    verbosity,
                    dl_reg,
                )
            )
            retlist.append(inst)
        finally:
            return retlist

    def get_message_data(self, resp_data, dl_reg=False):
        """Obtain relevant keys from rest response.

        :param resp: response
        :type resp: :class:`redfish.rest.containers.RestResponse`
        :returns: list of error response dictionaries
        """
        err_response_keys = ["MessageId", "Message", "MessageArgs", "Resolution"]
        try:
            if "messageid" in [_key.lower() for _key in resp_data.keys()]:
                data_extract = [resp_data]
            else:
                raise TypeError
        except (TypeError, KeyError):
            data_extract = json_traversal(resp_data, "messageid", ret_dict=True)
        if data_extract:
            try:
                if not dl_reg:
                    for inst in data_extract:
                        if [key.lower() for key in inst.keys()] not in [erk.lower() for erk in err_response_keys]:
                            if "messageid" in [str(key.lower()) for key in inst.keys()]:
                                inst.update(self.get_error_messages(inst[key]))
                                continue
            finally:
                return data_extract
        else:
            return None

    def verbosity_levels(
        self,
        message,
        messageid=" ",
        description=" ",
        resolution=" ",
        response_status=None,
        verbosity=0,
        dl_reg=False,
    ):
        """Formatting based on verbosity level.

        :param message: Message from BMC response combined with the registry model/schema.
        :type message: str
        :param messageid: Error code as classified by the BMC's error code registry.
        :type messageid: str
        :param resolution: Message from BMC registry model/schema with the suggested
                           resolution for the given error.
        :type resolution: str
        :param response_status: HTTP response status code.
        :type response_status: int
        :param verbosity: Option to set/control output message (stderr) verbosity.
        :type verbosity: int
        :returns: Message to be returned to caller.
        """
        resp_str = ""
        if response_status:
            resp_str = "[" + str(response_status) + "] "

        if (verbosity == 1 or dl_reg) and message:
            return resp_str + message + "\n"
        elif verbosity > 1 and messageid and message and resolution:
            if not resp_str:
                resp_str = "None "
            return (
                "\nHTTP Response Code: "
                + resp_str[:-1]
                + "\nMessageId: "
                + messageid
                + "\nDescription: "
                + description
                + "\nMessage: "
                + message
                + "\nResolution: "
                + resolution
                + "\n"
            )
        else:
            if response_status == 400:
                return "" + message + "\n"
            else:
                return ""

    # unused? (removal pending)
    @staticmethod
    def _get_errmsg_type(results):
        """Return the registry type of a response.

        :param resuts: rest response.
        :type results: RestResponse.
        :returns: returns a Registry Id type string, None if not match is found, or no_id if the
                  response is not an error message.
        """
        return get_errmsg_type(results)

    def get_error_messages(self, regtype=None):
        """Returns registry error messages. Can specify a specific registry to return by Id.

        :param regtype: Id of registry type to add to list.
        :type regtype: str
        :returns: A list of error messages.
        """
        LOGGER.info("Entering validation...")
        messages = None
        errmessages = {}
        reglist = []

        # An error occurred during the shortcut method so let's go through each registry,
        # obtain the schema and narrow down the selected schema for the registry type provided
        try:
            _regtype = regtype.split(".")[0]
            for reg in self.validation_mgr.iterregmems():
                # gen 10 / gen 9 rest
                if _regtype:
                    if reg and "Id" in reg and reg["Id"] == _regtype:
                        try:
                            reglist.append(reg["Registry"])
                        except KeyError:
                            reglist.append(reg["Schema"])
                        break
                    else:
                        continue

            if not reglist:
                # gen 9 redfish
                regval = [reg.get(arg, None) for arg in ["Registry", "Schema", "Id"]]
                regval = next(
                    (val for val in regval if val and "biosattributeregistry" not in val),
                    None,
                )
                if not regval and reg:
                    reg = reg["@odata.id"].split("/")
                    reg = reg[len(reg) - 2]
                    if "biosattributeregistry" not in reg.lower():
                        reglist.append(reg)
                elif regval:
                    reglist.append(regval)

            for reg in reglist:
                reg = reg.replace("%23", "#")
                messages = self.validation_mgr.get_registry_model(
                    getmsg=True, currtype=reg, searchtype=self.msg_reg_type
                )
                if messages:
                    errmessages.update(messages.get(next(iter(messages)))[regtype.split(".")[-1]])
            if not reglist or not errmessages:
                raise Exception
        except Exception:
            raise EmptyRaiseForEAFP("Unable to find registry schema with provided registry " "type: %s" % regtype)
        else:
            return errmessages
