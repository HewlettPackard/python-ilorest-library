###
# Copyright 2024 Hewlett Packard Enterprise, Inc. All rights reserved.
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
"""Base implementation for interaction with vnic interface"""

from redfish.rest.connections import ChifDriverMissingOrNotFound, VnicNotEnabledError
from redfish.rest.v1 import InvalidCredentialsError
from ctypes import *
import logging
import os

from redfish.hpilo.risblobstore2 import BlobStore2
from redfish.hpilo.rishpilo import BlobReturnCodes

if os.name == "nt":
    from ctypes import windll
else:
    from _ctypes import dlclose

# ---------End of imports---------
# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


class GenerateAndSaveAccountError(Exception):
    """Raised when errors occured while generating and saving app account"""

    pass


class RemoveAccountError(Exception):
    """Raised when errors occured while removing app account"""

    pass


class AppAccountExistsError(Exception):
    """Raised when errors occured while removing app account"""

    pass


class VnicLoginError(Exception):
    """Raised when error occurs while VNIC login"""

    pass


class AppIdListError(Exception):
    """Raised when error occurs during CompareAppIds"""

    pass


class SavinginTPMError(Exception):
    """Raised when error occurs while saving app account in TPM"""

    pass


class SavinginiLOError(Exception):
    """Raised when error occurs while saving app account in iLO"""

    pass


class GenBeforeLoginError(Exception):
    """Raised when error occurs while getting iLO Gen before login"""

    pass


class InvalidCommandLineError(Exception):
    """Raised when invalid command line arguments are passed"""

    pass


class AppAccount(object):
    def __init__(self, appname=None, appid=None, salt=None, username=None, password=None, log_dir=None):
        """Initialize the AppAccount object and configure logging."""
        self.appname = (appname or "self_register").encode("utf-8")
        self.dll = BlobStore2.gethprestchifhandle()
        self.salt = (salt or "self_register").encode("utf-8")
        self.username = username
        self.password = password
        self.log_dir = log_dir

        if log_dir and LOGGER.isEnabledFor(logging.DEBUG):
            logdir_c = create_string_buffer(log_dir.encode("utf-8"))
            self.dll.enabledebugoutput(logdir_c)
            LOGGER.info("Debug output enabled. Logs stored in: %s", log_dir)

        if appid and len(appid) == 4:
            appid = self.ExpandAppId(appid)

        self.appid = (appid or "self_register").encode("utf-8")

    def ExpandAppId(self, appid):
        """Calls the DLL function to expand a 4-character app ID."""
        self.dll.ExpandAppid.argtypes = [c_char_p, POINTER(c_char_p)]
        self.dll.ExpandAppid.restype = c_int

        host_app_id_c = c_char_p(appid.encode('utf-8'))
        expanded_app_id_c = c_char_p(None)

        ret = self.dll.ExpandAppid(host_app_id_c, byref(expanded_app_id_c))
        if ret:
            LOGGER.error("Error occured while locating the application account.")
            raise AppAccountExistsError()

        return expanded_app_id_c.value.decode('utf-8') if expanded_app_id_c else None

    def generate_and_save_apptoken(self):
        """Generate and save an application account, logging each step."""
        LOGGER.info("Starting generate_and_save_apptoken process.")

        self.dll.GenerateAppToken.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
        self.dll.GenerateAppToken.restype = c_int

        self.username = self.username.encode("utf-8")
        self.password = self.password.encode("utf-8")

        LOGGER.debug("Calling GenerateAppToken for AppID: %s", self.appid.decode("utf-8"))

        returncode = self.dll.GenerateAppToken(self.appid, self.appname, self.salt, self.username, self.password)

        if returncode == BlobReturnCodes.SUCCESS:
            LOGGER.info("Application account successfully generated and saved.")
            return BlobReturnCodes.SUCCESS
        elif returncode == -54:
            LOGGER.error("Failed to save account in TPM.")
            raise SavinginTPMError()
        elif returncode == -53:
            LOGGER.error("Failed to save account in iLO.")
            raise SavinginiLOError()
        elif returncode == -55:
            LOGGER.warning("Application account already exists.")
            raise AppAccountExistsError()
        elif returncode == -8:
            raise InvalidCredentialsError(0)
        else:
            LOGGER.critical("Unknown return code: %d", returncode)
            raise GenerateAndSaveAccountError()

    def remove_apptoken(self):
        returncode = 1
        if self.username and self.password:
            self.dll.DeleteAppTokenUsingCreds.argtypes = [c_char_p, c_char_p, c_char_p]
            self.dll.DeleteAppTokenUsingCreds.restype = c_int
            self.username = self.username.encode("utf-8")
            self.password = self.password.encode("utf-8")
            returncode = self.dll.DeleteAppTokenUsingCreds(self.appid, self.username, self.password)

        elif self.appname and self.salt:
            self.dll.DeleteAppToken.argtypes = [c_char_p, c_char_p, c_char_p]
            self.dll.DeleteAppToken.restype = c_int
            returncode = self.dll.DeleteAppToken(self.appid, self.appname, self.salt)

        if returncode == BlobReturnCodes.SUCCESS:
            return BlobReturnCodes.SUCCESS
        elif returncode == -8:
            raise InvalidCredentialsError(0)
        else:
            raise RemoveAccountError("Error occurred while removing app account.")

    def apptoken_exists(self):
        """Check if an application account exists in TPM."""
        LOGGER.info("Checking if application account exists.")

        self.dll.AppIdExistsinTPM.argtypes = [c_char_p, POINTER(c_bool)]
        self.dll.AppIdExistsinTPM.restype = c_int

        vexists = c_bool(False)
        returncode = self.dll.AppIdExistsinTPM(self.appid, byref(vexists))

        if returncode == BlobReturnCodes.SUCCESS:
            LOGGER.info("app account existence check completed. Exists: %s", vexists.value)
            return vexists.value
        else:
            LOGGER.error("Error occurred while checking if application account exists.")
            raise AppAccountExistsError()

    def vlogin(self):
        LOGGER.info("Starting VNIC login process.")

        self.dll.GetSessionID.argtypes = [c_char_p, c_char_p, c_char_p, POINTER(c_char_p), POINTER(c_char_p)]
        self.dll.GetSessionID.restype = c_int
        session_id = c_char_p()
        session_location = c_char_p()
        errorcode = 0

        try:
            errorcode = self.dll.GetSessionID(self.appid, self.appname, self.salt, byref(session_id),
                                              byref(session_location))
            if errorcode != BlobReturnCodes.SUCCESS:
                raise Exception
            session_id = session_id.value.decode()
            session_location = session_location.value.decode()
            session_location = "/" + session_location.split("/", 3)[-1]
            LOGGER.info("VNIC login successful. Session Location: %s, Session ID: ****%s",
                        session_location, session_id[-4:])

            return session_id, session_location
        except Exception as excp:
            LOGGER.error("VNIC login failed: %s", str(excp))
            raise VnicLoginError()

    def vnic_exists(self):
        """Check if the VNIC is ready for use."""
        LOGGER.info("Checking if VNIC is ready for use.")

        self.dll.ReadyToUse.restype = c_int
        status = self.dll.ReadyToUse()

        if status == BlobReturnCodes.SUCCESS:
            LOGGER.info("VNIC is ready for use.")
            return True
        else:
            LOGGER.warning("VNIC is not ready for use.")
            return False

    def version_beforelogin(self):
        """Detect the iLO version before login."""
        LOGGER.info("Detecting iLO version before login.")

        self.dll.DetectILO.argtypes = [c_char_p, POINTER(c_int), POINTER(c_int)]
        self.dll.DetectILO.restype = c_int

        ilo_type = c_int(0)
        security_state = c_int(0)

        if not self.appid:
            self.appid = "self_register".encode("utf-8")

        returncode = self.dll.DetectILO(self.appid, byref(ilo_type), byref(security_state))

        if returncode == BlobReturnCodes.SUCCESS:
            LOGGER.info("iLO version successfully detected: %d, Security State: %d",
                        ilo_type.value, security_state.value)
            return ilo_type.value, security_state.value
        elif returncode == -1 and ilo_type.value == 100:
            LOGGER.info("Detectilo returned ilotype: %d, Security State: %d, "
                        "returncode: %d", ilo_type.value, security_state.value, returncode)
            raise ChifDriverMissingOrNotFound()
        elif returncode == -50 and ilo_type.value == 101:
            LOGGER.info("Detectilo returned ilotype: %d, Security State: %d, "
                        "returncode: %d", ilo_type.value, security_state.value, returncode)
            raise VnicNotEnabledError()
        elif returncode == -2:
            LOGGER.info("Invalid parameters were passed in the command line. Detectilo iLO returncode: -2")
            raise InvalidCommandLineError()
        else:
            LOGGER.info("Detectilo returned ilotype: %d, Security State: %d, "
                        "returncode: %d", ilo_type.value, security_state.value, returncode)
            LOGGER.error("Failed to detect iLO version.")
            raise GenBeforeLoginError()

    def GetIPAddress(self):
        """Retrieve the IP address of the iLO interface."""
        LOGGER.info("Retrieving IP address.")

        self.dll.GetIPAddress.restype = c_wchar_p
        ip_addr = self.dll.GetIPAddress()

        LOGGER.info("IP address retrieved: %s", ip_addr)
        return ip_addr

    def CompareAppIds(self):
        """Compare application IDs and return a structured dictionary."""
        LOGGER.info("Starting CompareAppIds process.")

        self.dll.CompareAppIds.argtypes = [
            c_char_p,
            c_char_p,
            c_char_p,
            POINTER(POINTER(c_char_p)),
            POINTER(POINTER(c_char_p)),
            POINTER(c_int),
            POINTER(POINTER(c_uint8)),
            POINTER(POINTER(c_uint8)),
        ]
        self.dll.CompareAppIds.restype = c_int

        app_ids_ptr = POINTER(c_char_p)()
        app_names_ptr = POINTER(c_char_p)()
        app_id_count = c_int()
        in_tpm_ptr = POINTER(c_uint8)()
        in_ilo_ptr = POINTER(c_uint8)()

        LOGGER.debug(
            "Calling CompareAppIds with AppID: %s, AppName: %s",
            self.appid.decode("utf-8"),
            self.appname.decode("utf-8"),
        )

        returncode = self.dll.CompareAppIds(
            self.appid,
            self.appname,
            self.salt,
            byref(app_ids_ptr),
            byref(app_names_ptr),
            byref(app_id_count),
            byref(in_tpm_ptr),
            byref(in_ilo_ptr),
        )
        if returncode != BlobReturnCodes.SUCCESS:
            LOGGER.error("Error occurred in CompareAppIds. Return Code: %d", returncode)
            raise AppIdListError("Error occurred while retrieving App Id information.\n")

        LOGGER.info("CompareAppIds executed successfully. Number of App IDs: %d", app_id_count.value)
        app_ids = [app_ids_ptr[i].decode("utf-8") for i in range(app_id_count.value)]
        app_names = [app_names_ptr[i].decode("utf-8") for i in range(app_id_count.value)]
        in_tpm_list = [bool(in_tpm_ptr[i]) for i in range(app_id_count.value)]
        in_ilo_list = [bool(in_ilo_ptr[i]) for i in range(app_id_count.value)]

        appid_dict = list()
        for i in range(app_id_count.value):
            appid_dict.append(
                {
                    "ApplicationID": app_ids[i],
                    "ApplicationName": app_names[i],
                    "ExistsInTPM": in_tpm_list[i],
                    "ExistsIniLO": in_ilo_list[i],
                }
            )

        LOGGER.info("CompareAppIds completed successfully. Processed %d AppIDs.", len(appid_dict))

        return appid_dict
