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
import logging
from ctypes import (
    POINTER,
    byref,
    c_bool,
    c_char_p,
    c_int,
    c_uint8,
    c_wchar_p,
    create_string_buffer,
)

from redfish.hpilo.risblobstore2 import BlobStore2
from redfish.hpilo.rishpilo import BlobReturnCodes
from redfish.log_utils import RestDebugLogRotator


# ---------End of imports---------
# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


RETURN_CODE_TPM_NV_DEFINE_FAILED = -38
RETURN_CODE_TPM_GET_CAPABILITY_FAILED = -40
RETURN_CODE_CANT_VALIDATE_CA = -27
RETURN_CODE_TPM_OWNER_AUTH_REQUIRED = -63
RETURN_CODE_TPM_BAD_AUTH = -65
RETURN_CODE_TPM_NV_LOCKED = -66
RETURN_CODE_TPM_DA_LOCKOUT = -67


class GenerateAndSaveAccountError(Exception):
    """Raised when errors occured while generating and saving app account"""

    pass


class ReactivateAppAccountTokenError(Exception):
    """Raised when errors occurred while reactivating app account"""

    pass

class InactiveAppAccountTokenError(Exception):
    """Raised when inactive app account token"""

    pass


class RemoveAccountError(Exception):
    """Raised when errors occured while removing app account"""

    pass


class AppAccountExistsError(Exception):
    """Raised when errors occured while removing app account"""

    pass


class OrphanedAppAccountError(RemoveAccountError):
    """Raised when the app account exists in iLO but not in TPM (e.g. after TPM clear).
    Credentials are required to remove the orphaned iLO account."""

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


class TPMBadAuthError(Exception):
    """Raised when TPM bad owner authentication value is provided while saving app account in TPM"""

    pass


class TPMProvisionedAuthRequiredError(Exception):
    """Raised when TPM owner authorization is required for TPM operations"""

    pass


class TPMGetCapabilityFailedError(Exception):
    """Raised when TPM GetCapability API call fails"""

    pass


class TPMNVDefineFailedError(Exception):
    """Raised when TPM NV_Define API call fails"""

    pass


class TPMNVLockedOutError(Exception):
    """Raised when TPM NV access is locked"""

    pass


class TPMNVLockoutError(Exception):
    """Raised when TPM is in DA lockout mode"""

    pass


class CantValidateCAError(Exception):
    """Raised when the certificate CA chain cannot be validated (RC -27)"""

    pass


class ReactivateTPMBadAuthError(Exception):
    """Raised when TPM bad authentication occurs during reactivate app account"""

    pass


class ReactivateTPMProvisionedAuthRequiredError(Exception):
    """Raised when TPM owner authorization is required for TPM operations during reactivate app account"""

    pass


class ReactivateTPMGetCapabilityFailedError(Exception):
    """Raised when TPM GetCapability API call fails during reactivate app account"""

    pass


class ReactivateTPMNVDefineFailedError(Exception):
    """Raised when TPM NV_Define API call fails during reactivate app account"""

    pass


class ReactivateTPMNVLockedOutError(Exception):
    """Raised when TPM NV access is locked during reactivate app account"""

    pass


class ReactivateTPMNVLockoutError(Exception):
    """Raised when TPM is in DA lockout mode during reactivate app account"""

    pass


class GenBeforeLoginError(Exception):
    """Raised when error occurs while getting iLO Gen before login"""

    pass


class InvalidCommandLineError(Exception):
    """Raised when invalid command line arguments are passed"""

    pass


class AppAccount(object):
    def __init__(self, appname=None, appid=None, salt=None, username=None, password=None, owner_auth=None, log_dir=None):
        """Initialize the AppAccount object and configure logging."""
        self.appname = (appname or "self_register").encode("utf-8")
        self.dll = BlobStore2.gethprestchifhandle()
        self.salt = (salt or "self_register").encode("utf-8")
        self.username = username
        self.password = password
        self.owner_auth = owner_auth
        self.log_dir = log_dir

        LOGGER.debug(
            f"Initialization parameters - AppName: {self.appname.decode('utf-8')}, "
            f"Salt: {self.salt.decode('utf-8')}, Username: {self.username if self.username else 'None'}"
        )

        if log_dir and LOGGER.isEnabledFor(logging.DEBUG):
            # Rotate rest.debug.log if it exceeds size threshold
            RestDebugLogRotator.rotate_rest_debug_log(log_dir, max_size_mb=2.0, max_backups=3)

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

        host_app_id_c = c_char_p(appid.encode("utf-8"))
        expanded_app_id_c = c_char_p(None)

        LOGGER.debug(f"Calling ExpandAppid with AppID: {appid}")
        ret = self.dll.ExpandAppid(host_app_id_c, byref(expanded_app_id_c))
        if ret:
            LOGGER.error(f"Failed to expand App ID {appid} (Return code: {ret})")
            raise AppAccountExistsError()

        expanded_id = expanded_app_id_c.value.decode("utf-8") if expanded_app_id_c else None
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug(f"Successfully expanded App ID {appid} to {expanded_id}")
        return expanded_id

    def generate_and_save_apptoken(self):
        """Generate and save an application account, logging each step."""
        LOGGER.info("Starting generate_and_save_apptoken process.")

        self.dll.GenerateAppToken.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
        self.dll.GenerateAppToken.restype = c_int

        self.username = self.username.encode("utf-8")
        self.password = self.password.encode("utf-8")
        # Use b"" (not "") so ctypes c_char_p receives bytes, not a bare str.
        owner_auth = self.owner_auth.encode("utf-8") if self.owner_auth else b""

        LOGGER.debug("Calling GenerateAppToken for AppID: %s", self.appid.decode("utf-8"))

        returncode = self.dll.GenerateAppToken(self.appid, self.appname, self.salt, self.username, self.password, owner_auth)

        if returncode in (BlobReturnCodes.SUCCESS, 1):
            # RC 0  = success; RC +1 = HPSRV_RC_AutoProvisioningEnabled — Windows
            # manages the TPM owner key, account created successfully without
            # an explicit owner_auth.
            if returncode == 1:
                LOGGER.debug("GenerateAppToken returned +1 (Windows auto-provisioning active); treating as success.")
            LOGGER.info("Application account successfully generated and saved.")
            return BlobReturnCodes.SUCCESS
        elif returncode == -54:
            LOGGER.debug("Failed to save account in TPM.")
            raise SavinginTPMError()
        elif returncode == -53:
            LOGGER.debug("Failed to save account in iLO.")
            raise SavinginiLOError()
        elif returncode == -55:
            LOGGER.warning("Application account already exists.")
            raise AppAccountExistsError()
        elif returncode == -8:
            raise InvalidCredentialsError(0)
        elif returncode == RETURN_CODE_CANT_VALIDATE_CA:
            LOGGER.debug("Can't validate certificate CA chain.")
            raise CantValidateCAError()
        elif returncode in (RETURN_CODE_TPM_BAD_AUTH, -64):
            # -65 = HPSRV_RC_TPMBadAuth; -64 = HPSRV_RC_TPMAuthFail (defensive alias)
            LOGGER.debug("TPM authorization failed with invalid authorization value provided.")
            raise TPMBadAuthError()
        elif returncode == RETURN_CODE_TPM_OWNER_AUTH_REQUIRED:
            LOGGER.debug("TPM is provisioned owner auth is required for TPM operations.")
            raise TPMProvisionedAuthRequiredError()
        elif returncode == RETURN_CODE_TPM_GET_CAPABILITY_FAILED:
            LOGGER.debug("TPM GetCapability API Failed.")
            raise TPMGetCapabilityFailedError()
        elif returncode == RETURN_CODE_TPM_NV_DEFINE_FAILED:
            LOGGER.debug("TPM NV_Define API Failed.")
            raise TPMNVDefineFailedError()
        elif returncode == RETURN_CODE_TPM_NV_LOCKED:
            LOGGER.debug("TPM NV access is locked.")
            raise TPMNVLockedOutError()
        elif returncode == RETURN_CODE_TPM_DA_LOCKOUT:
            LOGGER.debug("TPM is in DA lockout mode.")
            raise TPMNVLockoutError()
        else:
            LOGGER.critical("Unknown return code: %d", returncode)
            raise GenerateAndSaveAccountError()

    def reactivate_apptoken(self):
        """Reactivate an application account, logging each step."""
        LOGGER.info("Starting reactivate_apptoken process.")

        self.dll.ReactivateAppToken.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
        self.dll.ReactivateAppToken.restype = c_int

        user_name = self.username.encode("utf-8")
        password = self.password.encode("utf-8")
        # Use b"" (not "") so ctypes c_char_p receives bytes, not a bare str.
        owner_auth = self.owner_auth.encode("utf-8") if self.owner_auth else b""

        LOGGER.debug("Calling ReactivateAppToken for AppID: %s", self.appid.decode("utf-8"))

        return_code = self.dll.ReactivateAppToken(self.appid, self.appname, self.salt, user_name, password, owner_auth)

        if return_code in (BlobReturnCodes.SUCCESS, 1):
            # RC +1 = HPSRV_RC_AutoProvisioningEnabled; treat as success.
            LOGGER.info("Application account has been reactivated successfully.")
            return BlobReturnCodes.SUCCESS
        elif return_code == -8:
            # Surfaced once by the centralized handler; keep a debug trace only.
            LOGGER.debug("Invalid credentials during reactivate (RC -8).")
            raise InvalidCredentialsError(0)
        elif return_code == RETURN_CODE_CANT_VALIDATE_CA:
            LOGGER.debug("Can't validate certificate CA chain during reactivate.")
            raise CantValidateCAError()
        elif return_code in (RETURN_CODE_TPM_BAD_AUTH, -64):
            # -65 = HPSRV_RC_TPMBadAuth; -64 = HPSRV_RC_TPMAuthFail (defensive alias)
            LOGGER.debug("TPM authorization failed with invalid authorization value provided.")
            raise ReactivateTPMBadAuthError()
        elif return_code == RETURN_CODE_TPM_OWNER_AUTH_REQUIRED:
            LOGGER.debug("TPM is provisioned owner auth is required for TPM operations.")
            raise ReactivateTPMProvisionedAuthRequiredError()
        elif return_code == RETURN_CODE_TPM_GET_CAPABILITY_FAILED:
            LOGGER.debug("TPM GetCapability API Failed.")
            raise ReactivateTPMGetCapabilityFailedError()
        elif return_code == RETURN_CODE_TPM_NV_DEFINE_FAILED:
            LOGGER.debug("TPM NV_Define API Failed.")
            raise ReactivateTPMNVDefineFailedError()
        elif return_code == RETURN_CODE_TPM_NV_LOCKED:
            LOGGER.debug("TPM NV access is locked.")
            raise ReactivateTPMNVLockedOutError()
        elif return_code == RETURN_CODE_TPM_DA_LOCKOUT:
            LOGGER.debug("TPM is in DA lockout mode.")
            raise ReactivateTPMNVLockoutError()
        else:
            LOGGER.critical("Unknown return code: %d", return_code)
            raise ReactivateAppAccountTokenError()

    def remove_apptoken(self):
        returncode = 1
        if self.username and self.password:
            LOGGER.debug(f"Using credentials to remove for AppID: {self.appid.decode('utf-8')}")
            self.dll.DeleteAppTokenUsingCreds.argtypes = [c_char_p, c_char_p, c_char_p]
            self.dll.DeleteAppTokenUsingCreds.restype = c_int
            self.username = self.username.encode("utf-8")
            self.password = self.password.encode("utf-8")
            returncode = self.dll.DeleteAppTokenUsingCreds(self.appid, self.username, self.password)

        elif self.appname and self.salt:
            LOGGER.debug(f"Using app details to remove for AppID : {self.appid.decode('utf-8')}")
            self.dll.DeleteAppToken.argtypes = [c_char_p, c_char_p, c_char_p]
            self.dll.DeleteAppToken.restype = c_int
            returncode = self.dll.DeleteAppToken(self.appid, self.appname, self.salt)

            # When TPM has been cleared the local token is gone, but the account may
            # still exist in iLO (orphaned). DeleteAppToken cannot authenticate in that
            # state, so detect the condition and surface a specific error so the caller
            # can advise the user to re-run with credentials to finish the cleanup.
            if returncode != BlobReturnCodes.SUCCESS:
                LOGGER.warning(
                    "DeleteAppToken failed (code: %d). TPM may have been cleared. "
                    "Checking whether the account is orphaned in iLO.",
                    returncode,
                )
                try:
                    exists_in_tpm = self.apptoken_exists()
                except AppAccountExistsError:
                    exists_in_tpm = True  # check failed; assume token is present, raise generic error below
                if not exists_in_tpm:
                    LOGGER.error(
                        "App account is not present in TPM but may still exist in iLO. "
                        "Re-run the delete command with --username / --password to remove "
                        "the orphaned iLO account."
                    )
                    raise OrphanedAppAccountError(
                        "App account token was not found in TPM (TPM may have been cleared). "
                        "The account may still exist in iLO. "
                        "Re-run with credentials to remove it."
                    )

        LOGGER.debug(f"Delete operation returned code: {returncode}")

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
        LOGGER.debug(f"Checking existence for AppID: {self.appid.decode('utf-8')}")
        returncode = self.dll.AppIdExistsinTPM(self.appid, byref(vexists))
        LOGGER.debug(f"AppIdExistsinTPM returned: {returncode}")

        if returncode == BlobReturnCodes.SUCCESS:
            LOGGER.info("app account existence check completed. Exists: %s", vexists.value)
            return vexists.value
        else:
            LOGGER.error("Failed to check account existence")
            LOGGER.debug(f"Failed with return code: {returncode}")
            raise AppAccountExistsError()

    def vlogin(self):
        LOGGER.info("Starting VNIC login process.")

        self.dll.GetSessionID.argtypes = [c_char_p, c_char_p, c_char_p, POINTER(c_char_p), POINTER(c_char_p)]
        self.dll.GetSessionID.restype = c_int
        session_id = c_char_p()
        session_location = c_char_p()
        errorcode = 0

        LOGGER.debug(f"Attempting login for AppID: {self.appid.decode('utf-8')}")
        try:
            errorcode = self.dll.GetSessionID(
                self.appid, self.appname, self.salt, byref(session_id), byref(session_location)
            )
            LOGGER.debug(f"GetSessionID returned code: {errorcode}")
            if errorcode == 2:
                raise InactiveAppAccountTokenError()
            elif errorcode != BlobReturnCodes.SUCCESS:
                raise Exception

            # Defensive validation of the native call's output: a SUCCESS return
            # code with an empty/None session id or location is a contract
            # violation and must not be passed downstream. Historically this was
            # seen under concurrent TPM access when the named TPM semaphore was
            # destroyed by another process's disconnect (fixed in the CHIF DLL by
            # not calling sem_unlink on release); it can still occur when running
            # against an older/unfixed ilorest_chif or under transient TPM
            # contention. Treat it as a retryable VnicLoginError with a clear
            # message rather than returning an empty session that surfaces
            # downstream as the confusing generic "Empty Session Id or Session
            # Location was returned." error.
            if not session_id.value or not session_location.value:
                LOGGER.error(
                    "GetSessionID reported success but returned an empty session "
                    "(AppID: %s). This can indicate transient TPM semaphore "
                    "contention when multiple processes access the TPM concurrently "
                    "(e.g. against an older ilorest_chif). The operation can be retried.",
                    self.appid.decode("utf-8"),
                )
                raise VnicLoginError()

            session_id = session_id.value.decode()
            session_location = session_location.value.decode()
            session_location = "/" + session_location.split("/", 3)[-1]
            LOGGER.debug("Successfully decoded session information")
            LOGGER.info(
                "VNIC login successful. Session Location: %s, Session ID: ****%s", session_location, session_id[-4:]
            )

            return session_id, session_location
        except InactiveAppAccountTokenError:
            LOGGER.error("Login failed due to an inactive or expired App Account token.")
            raise InactiveAppAccountTokenError()
        except Exception as excp:
            LOGGER.error("VNIC login failed: %s", str(excp))
            raise VnicLoginError()

    def vnic_exists(self):
        """Check if the VNIC is ready for use."""
        LOGGER.info("Checking if VNIC is ready for use.")

        self.dll.ReadyToUse.restype = c_int
        LOGGER.debug("Calling ReadyToUse")
        status = self.dll.ReadyToUse()
        LOGGER.debug(f"ReadyToUse returned status: {status}")

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
        LOGGER.debug(f"DetectILO returned: type={ilo_type.value}, security={security_state.value}, code={returncode}")

        if returncode == BlobReturnCodes.SUCCESS:
            LOGGER.info(
                "iLO version successfully detected: %d, Security State: %d", ilo_type.value, security_state.value
            )
            return ilo_type.value, security_state.value
        elif returncode == -1 and ilo_type.value == 100:
            LOGGER.info(
                "Detectilo returned ilotype: %d, Security State: %d, " "returncode: %d",
                ilo_type.value,
                security_state.value,
                returncode,
            )
            raise ChifDriverMissingOrNotFound()
        elif returncode == -50 and ilo_type.value == 101:
            LOGGER.info(
                "Detectilo returned ilotype: %d, Security State: %d, " "returncode: %d",
                ilo_type.value,
                security_state.value,
                returncode,
            )
            raise VnicNotEnabledError()
        elif returncode == -2:
            LOGGER.info("Invalid parameters were passed in the command line. Detectilo iLO returncode: -2")
            raise InvalidCommandLineError()
        else:
            LOGGER.info(
                "Detectilo returned ilotype: %d, Security State: %d, " "returncode: %d",
                ilo_type.value,
                security_state.value,
                returncode,
            )
            LOGGER.error("Failed to detect iLO version.")
            raise GenBeforeLoginError()

    def GetIPAddress(self):
        """Retrieve the IP address of the iLO interface."""
        LOGGER.info("Retrieving IP address.")

        LOGGER.debug("Calling GetIPAddress")
        self.dll.GetIPAddress.restype = c_wchar_p
        ip_addr = self.dll.GetIPAddress()
        LOGGER.debug(f"GetIPAddress returned: {ip_addr if ip_addr else 'None'}")

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
        if returncode == -62:
            LOGGER.debug("AppAccount is inactive. Please run the appaccount reactivate command.")
            raise InactiveAppAccountTokenError()
        elif returncode == -8:
            LOGGER.debug("No app accounts found. CompareAppIds Return Code: %d", returncode)
            return []
        elif returncode != BlobReturnCodes.SUCCESS:
            LOGGER.debug("Error occurred in CompareAppIds. Return Code: %d", returncode)
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
