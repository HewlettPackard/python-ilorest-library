 # Copyright 2020 Hewlett Packard Enterprise Development LP
 #
 # Licensed under the Apache License, Version 2.0 (the "License"); you may
 # not use this file except in compliance with the License. You may obtain
 # a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 # WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 # License for the specific language governing permissions and limitations
 # under the License.

# -*- coding: utf-8 -*-
"""
An example of getting the ilo information like ilo generation, version and resource directory for HPE iLO systems
"""

import sys
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

def get_resource_directory(redfishobj):

    try:
        resource_uri = redfishobj.root.obj.Oem.Hpe.Links.ResourceDirectory['@odata.id']
    except KeyError:
        sys.stderr.write("Resource directory is only available on HPE servers.\n")
        return None

    response = redfishobj.get(resource_uri)
    resources = []

    if response.status == 200:
        sys.stdout.write("\tFound resource directory at /redfish/v1/resourcedirectory" + "\n\n")
        resources = response.dict["Instances"]
    else:
        sys.stderr.write("\tResource directory missing at /redfish/v1/resourcedirectory" + "\n")

    return resources

def get_gen(_redfishobj):
	rootresp = _redfishobj.root.obj
	#Default iLO 5
	ilogen = 5
	gencompany = next(iter(rootresp.get("Oem", {}).keys()), None) in ('Hpe', 'Hp')
	comp = 'Hp' if gencompany else None
	comp = 'Hpe' if rootresp.get("Oem", {}).get('Hpe', None) else comp
	if comp and next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).\
																get('ManagerType', None):
		ilogen = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {})))\
																		.get("ManagerType")
		ilover = next(iter(rootresp.get("Oem", {}).get(comp, {}).get("Manager", {}))).\
															  get("ManagerFirmwareVersion")
		if ilogen.split(' ')[-1] == "CM":
			# Assume iLO 4 types in Moonshot
			ilogen = 4
			iloversion = None
		else:
			ilogen = ilogen.split(' ')[1]
			iloversion = float(ilogen.split(' ')[-1] + '.' + \
											''.join(ilover.split('.')))
	return (ilogen, iloversion)
