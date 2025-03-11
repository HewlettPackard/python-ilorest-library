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
"""Compatibility functionality in between iLO versions and generic Redfish/LegacyRest servers.
Used to provide convenient string variables that are usable on any iLO irrespective of version or
API type."""
# ---------Imports---------
import logging

from redfish import LegacyRestClient, RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
from redfish.ris.rmc_helper import (
    NothingSelectedError,
    UnableToObtainIloVersionError,
    UserNotAdminError,
)

# ---------End of imports---------

LOGGER = logging.getLogger(__name__)


# TODO: This will be a part of the compatability class
class Typesandpathdefines(object):
    """The global types and path definitions class. Holds information on a system and automatically
    creates the correct type strings along with some generic paths. Paths are meant to be used with
    iLO systems. Paths may be different on generic Redfish systems. Self variables are created when
    the `getgen` function is called.

    Useful self variables that are created include:

    * **url**: The url of the system that the defines were created for.
    * **defs**: The string defines for the system that was passed to `getgen`. Includes key
      property keys, paths, types, and flags to check what the system type is.
    * **ilogen**: The iLO generation of the system that the defines were created for. For non-iLO
      Redfish systems this is set to **5**.
    * **iloversion**: The iLO version of the system that the defines were created for.
    * **flagiften**: Flag is set to true if the system is Gen 10 or a non-iLO Redfish system.
    """

    def __init__(self):
        self.url = None
        self.defs = None
        self.ilogen = None
        self.iloversion = None
        self.flagiften = False
        self.adminpriv = True

    def iLO7VersionCheck(self,rootresp):
        if "Oem" in rootresp:
            if "Hpe" in rootresp["Oem"]:
                gen = next(iter(rootresp.get("Oem", {}).get("Hpe", {}).get("Manager", {}))).get("ManagerType",
                                                                                                None)
            elif "Hp" in rootresp["Oem"]:
                gen = next(iter(rootresp.get("Oem", {}).get("Hp", {}).get("Manager", {}))).get("ManagerType",
                                                                                               None)
            else:
                raise Exception("Malformed Json")
            if gen:
                gen = gen.split(" ")[1]
            else:
                gen = rootresp.get("Oem", {}).get("Hpe", {}).get("Moniker", {}).get("PRODGEN").split(" ")[1]
            if int(gen) == 7:
                return True
        return False

    def getgen(
        self,
        gen=None,
        url=None,
        username=None,
        password=None,
        sessionid=None,
        logger=None,
        proxy=None,
        ca_cert_data={},
        isredfish=True,
        login_otp=None,
        log_dir=None,
        session_location=None,
    ):
        """Function designed to verify the servers platform. Will generate the `Typeandpathdefines`
        variables based on the system type that is detected.

        :param url: The URL to perform the request on.
        :type url: str
        :param username: The username to login with.
        :type username: str
        :param password: The password to login with.
        :type password: str
        :param proxy: The proxy to connect to the system with.
        :type proxy: str
        :param ca_certs: Dictionary including the TLS certificate information of user based
          authentication
        :type ca_certs: dict
        :param isredfish: The flag to force redfish conformance on iLO 4 systems. You will still
          need to call `updatedefinesflag` to update the defines to Redfish.
        :type isredfish: bool
        :param logger: The logger handler to log data too uses the default if none is provided.
        :type logger: str
        """

        if self.adminpriv is False and url.startswith("blob"):
            raise UserNotAdminError("")

        self.url = url
        self.is_redfish = isredfish
        self.gencompany = self.rootresp = False
        self.ilogen = 5  # If no iLO or Anonymous data , default to iLO 5 types
        logger = logger if not logger else LOGGER
        client = None
        self.noschemas = False
        self.schemapath = self.regpath = ""

        if not gen:
            try_count = 0
            try:
                client = RedfishClient(
                    base_url=self.url,
                    username=username,
                    password=password,
                    sessionid=sessionid,
                    proxy=proxy,
                    ca_cert_data=ca_cert_data,
                    login_otp=login_otp,
                    log_dir=log_dir,
                    session_location=session_location,
                )
                client._get_root()
            except ServerDownOrUnreachableError as excp:
                if self.is_redfish:
                    raise excp
                try_count += 1
            if not self.is_redfish:
                try:
                    restclient = LegacyRestClient(
                        base_url=self.url,
                        username=username,
                        password=password,
                        sessionid=sessionid,
                        proxy=proxy,
                        ca_cert_data=ca_cert_data,
                        login_otp=login_otp,
                        session_location=session_location,
                    )
                    restclient._get_root()
                    # Check that the response is actually legacy rest and not a redirect
                    _ = restclient.root.obj.Type
                    self.is_redfish = False
                    client = restclient
                except Exception as excp:
                    try_count += 1
                    if not client:
                        logger.info("Gen get rest error:" + str(excp) + "\n")
                        raise excp
                    else:
                        self.is_redfish = True

            if try_count > 1:
                raise ServerDownOrUnreachableError(
                    "Server not reachable or does not support " "HPRest or Redfish \n"
                )

            rootresp = client.root.obj
            self.rootresp = rootresp
            client.logout()
            iLO7 = False
            iLO7 = self.iLO7VersionCheck(rootresp)
            if not iLO7:
                self.gencompany = next(iter(self.rootresp.get("Oem", {}).keys()), None) in (
                    "Hpe",
                    "Hp",
                )
                comp = "Hp" if self.gencompany else None
                comp = "Hpe" if rootresp.get("Oem", {}).get("Hpe", None) else comp
                if comp and next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerType", None):
                    self.ilogen = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerType")
                    self.ilover = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).get(
                        "ManagerFirmwareVersion"
                    )
                    if self.ilogen.split(" ")[-1] == "CM":
                        # Assume iLO 4 types in Moonshot
                        self.ilogen = 4
                        self.iloversion = None
                    else:
                        self.iloversion = float(self.ilogen.split(" ")[-1] + "." + "".join(self.ilover.split(".")))
            else:
                self.ilogen = next(iter(rootresp.get("Oem", {}).get("Hpe", {}).get("Manager", {}))).get("ManagerType")
                self.ilover = next(iter(rootresp.get("Oem", {}).get("Hpe", {}).get("Manager", {}))).get(
                    "ManagerFirmwareVersion",None)
                if self.ilover is None:
                    self.ilover = "1.01.01"
                self.iloversion = float(self.ilogen.split(" ")[-1] + "." + "".join(self.ilover.split(".")))
        else:
            self.ilogen = int(gen)

        try:
            if not isinstance(self.ilogen, int):
                self.ilogen = int(self.ilogen.split(" ")[-1])
            self.flagiften = True if int(self.ilogen) >= 5 else False
        except:
            raise UnableToObtainIloVersionError("Unable to find the iLO generation.")

        self.noschemas = (
            True
            if self.rootresp and "JsonSchemas" in self.rootresp and not self.rootresp.get("JsonSchemas", None)
            else False
        )
        if self.noschemas:
            self.ilogen = self.ilover = self.iloversion = None
        if self.rootresp and not self.noschemas:
            self.defineregschemapath(self.rootresp)

        if self.flagiften:
            self.defs = Definevalstenplus()
        else:
            self.defs = DefinevalsNine()

    def defineregschemapath(self, rootobj):
        """Defines the schema and registry paths using data in root path.

        :param rootobj: The root path data.
        :type rootobj: dict.
        """
        iLO7 = False
        if self.iLO7VersionCheck(rootobj):
            self.gencompany = "Hpe"
        else:
            self.gencompany = next(iter(rootobj.get("Oem", {}).keys()), None) in ("Hpe", "Hp")
        self.schemapath = (
            rootobj["JsonSchemas"]["@odata.id"]
            if rootobj.get("JsonSchemas", None)
            else rootobj["links"]["Schemas"]["href"]
        )
        self.schemapath = (
            self.schemapath.rstrip("/") + "/?$expand=."
            if self.is_redfish and self.flagiften and self.gencompany
            else self.schemapath
        )
        self.regpath = (
            rootobj["Registries"]["@odata.id"]
            if rootobj.get("Registries", None)
            else rootobj["links"]["Registries"]["href"]
        )
        self.regpath = (
            self.regpath.rstrip("/") + "/?$expand=."
            if self.is_redfish and self.flagiften and self.gencompany
            else self.regpath
        )

    # TODO: Move these to a compatability class
    def updatedefinesflag(self, redfishflag=None):
        """Updates the redfish and rest flag depending on system and redfishflag input. On an iLO 5
        system or another Redfish system, this will do nothing. On an iLO 4 system with both Redfish
        and LegacyRest this will update the defines to redfish if the *redfishflag* is set to True
        and stay with the LegacyRest defines otherwise.

        :param redfishflag: User input for redfish
        :type redfishflag: bool
        :returns: True if the system should use Redfish, False for legacy Rest.
        :rtype: bool
        """
        if self.defs:
            is_redfish = redfishflag or self.defs.isgen10
            self.defs.flagforrest = not is_redfish
            if is_redfish:
                self.defs.redfishchange()

            return is_redfish
        else:
            return redfishflag

    def modifyselectorforgen(self, sel):
        """Changes the select to match the Generation's HP string based to the correct type for
        specific iLO versions.

        :param sel: query to be changed to match Generation's HP string
        :type sel: str
        :returns: A modified selector matching the Generation's HP string.
        :rtype: string
        """
        if not sel:
            raise NothingSelectedError()
        sel = sel.lower()
        returnval = sel

        if sel.startswith(("hpeeskm", "#hpeeskm", "hpeskm", "#hpeskm")):
            returnval = self.defs.hpeskmtype
        elif "bios." in sel[:9].lower():
            returnval = self.defs.biostype
        elif sel.startswith(("hpe", "#hpe")) and self.defs and self.defs.isgen9:
            returnval = sel[:4].replace("hpe", "hp") + sel[4:]
        elif not sel.startswith(("hpe", "#hpe")) and self.defs and self.defs.isgen10:
            returnval = sel[:3].replace("hp", "hpe") + sel[3:]

        return returnval


class Definevals(object):
    """Base class for setting platform dependent variables."""

    def __init__(self):
        pass


class Definevalstenplus(Definevals):
    """Platform dependent variables for iLO 5+ (Gen 10)."""

    # pylint: disable=too-many-instance-attributes
    # As a defines class this will need all the attributes
    def __init__(self):
        self.oemhp = "Hpe"

        self.oempath = "/Oem/Hpe"
        self.startpath = "/redfish/v1/"
        self.systempath = "/redfish/v1/Systems/1/"
        self.managerpath = "/redfish/v1/Managers/1/"
        self.biospath = "/redfish/v1/systems/1/bios/"
        self.addlicensepath = "/redfish/v1/Managers/1/LicenseService/"
        self.accountspath = "/redfish/v1/AccountService/Accounts/"
        self.federationpath = "/redfish/v1/Managers/1/FederationGroups/"
        self.resourcedirpath = "/redfish/v1/ResourceDirectory/"

        self.biostype = "Bios."
        self.hpeskmtype = "HpeESKM."
        self.hpcommontype = "HpeCommon"
        self.hpilossotype = "HpeiLOSSO."
        self.hpsecureboot = "SecureBoot."
        self.logservicetype = "#LogService."
        self.iscsisource = "iSCSISources"
        self.iscsiattemptinstance = "iSCSIAttemptInstance"
        self.iscsiattemptname = "iSCSIAttemptName"
        self.hphttpscerttype = "HpeHttpsCert."
        self.snmpservice = "HpeiLOSnmpService."
        self.attributenametype = "AttributeName"
        self.hpilodatetimetype = "HpeiLODateTime."
        self.attributeregtype = "#AttributeRegistry."
        self.hpilofirmwareupdatetype = "UpdateService."
        self.resourcedirectorytype = "HpeiLOResourceDirectory."
        self.hpilofederationgrouptype = "HpeiLOFederationGroup."
        self.managernetworkservicetype = "ManagerNetworkProtocol."
        self.schemafilecollectiontype = "#JsonSchemaFileCollection."
        self.regfilecollectiontype = "#MessageRegistryFileCollection."
        self.hpilolicensecollectiontype = "HpeiLOLicenseCollection."
        self.hpiloactivehealthsystemtype = "#HpeiLOActiveHealthSystem."
        self.securityservice = "HpeSecurityService."
        self.hpiscsisoftwareinitiatortype = "HpeiSCSISoftwareInitiator."
        self.hpilofederationgrouptypecoll = "HpeiLOFederationGroupCollection."
        self.bootoverridetargettype = "BootSourceOverrideTarget@Redfish.AllowableValues"
        self.messageregistrytype = "#MessageRegistry."

        self.typestring = "@odata.type"
        self.hrefstring = "@odata.id"
        self.collectionstring = "Members"
        self.biossettingsstring = "@Redfish.Settings"
        self.attname = "AttributeName"
        self.iscsistring = "iSCSISources"

        self.isgen9 = False
        self.isgen10 = True
        self.flagforrest = False
        super(Definevalstenplus, self).__init__()

    def redfishchange(self):
        """Empty function to update redfish variables (unneeded when the system is already redfish)."""
        pass


class DefinevalsNine(Definevals):
    """Platform dependent variables for iLO 4 LegacyRest (Gen 9)."""

    # pylint: disable=too-many-instance-attributes
    # As a defines class this will need all the attributes
    def __init__(self):
        self.oemhp = "Hp"

        self.oempath = "/Oem/Hp"
        self.startpath = "/rest/v1"
        self.systempath = "/rest/v1/Systems/1"
        self.managerpath = "/rest/v1/Managers/1"
        self.biospath = "/rest/v1/systems/1/bios"
        self.addlicensepath = "/rest/v1/Managers/1/LicenseService"
        self.accountspath = "/rest/v1/AccountService/Accounts"
        self.federationpath = "/rest/v1/Managers/1/FederationGroups"
        self.resourcedirpath = "/rest/v1/ResourceDirectory"

        self.biostype = "HpBios."
        self.hpeskmtype = "HpESKM."
        self.hpcommontype = "HpCommon"
        self.hpilossotype = "HpiLOSSO."
        self.snmpservice = "SnmpService."
        self.attributenametype = "Name"
        self.logservicetype = "LogService."
        self.iscsisource = "iSCSIBootSources"
        self.iscsiattemptinstance = "iSCSIBootAttemptInstance"
        self.iscsiattemptname = "iSCSIBootAttemptName"
        self.hpsecureboot = "HpSecureBoot."
        self.hphttpscerttype = "HpHttpsCert."
        self.hpilodatetimetype = "HpiLODateTime."
        self.hpilofirmwareupdatetype = "HpiLOFirmwareUpdate."
        self.resourcedirectorytype = "HpiLOResourceDirectory."
        self.hpilofederationgrouptype = "HpiLOFederationGroup."
        self.attributeregtype = "HpBiosAttributeRegistrySchema."
        self.schemafilecollectiontype = "#SchemaFileCollection."
        self.regfilecollectiontype = "#SchemaFileCollection."
        self.managernetworkservicetype = "ManagerNetworkService."
        self.hpiloactivehealthsystemtype = "HpiLOActiveHealthSystem."
        self.messageregistrytype = "MessageRegistry."
        self.hpilolicensecollectiontype = None
        self.hpilofederationgrouptypecoll = None
        self.bootoverridetargettype = "BootSourceOverrideSupported"
        self.hpiscsisoftwareinitiatortype = "HpiSCSISoftwareInitiator"

        self.typestring = "Type"
        self.hrefstring = "href"
        self.collectionstring = "Items"
        self.biossettingsstring = "SettingsResult"
        self.attname = "Name"
        self.iscsistring = "iSCSIBootSources"

        self.isgen9 = True
        self.isgen10 = False
        self.flagforrest = True
        super(DefinevalsNine, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables from LegacyRest to iLO 4 Redfish (Gen 9)."""
        self.startpath = "/redfish/v1/"
        self.systempath = "/redfish/v1/Systems/1/"
        self.managerpath = "/redfish/v1/Managers/1/"
        self.biospath = "/redfish/v1/systems/1/bios/"
        self.addlicensepath = "/redfish/v1/Managers/1/LicenseService/"
        self.resourcedirpath = "/redfish/v1/ResourceDirectory/"

        self.typestring = "@odata.type"
        self.hrefstring = "@odata.id"
        self.collectionstring = "Members"

        self.logservicetype = "#LogService."
        self.hpiloactivehealthsystemtype = "#HpiLOActiveHealthSystem."
        self.hpilolicensecollectiontype = "HpiLOLicenseCollection."
        self.hpilofederationgrouptypecoll = "HpiLOFederationGroupCollection."
        self.managernetworkservicetype = "ManagerNetworkProtocol."

        self.flagforrest = False
