 # Copyright 2019 Hewlett Packard Enterprise Development LP
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
An example of uploading a component to the iLO Repository for flashing
"""

import os
import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

from get_resource_directory import get_resource_directory

def upload_firmware(_redfishobj, firmware_loc, compsig_loc, update_repo=True, update_target=False):
    resource_instances = get_resource_directory(_redfishobj)

    if DISABLE_RESOURCE_DIR or not resource_instances:
        #resource directory is not available so we will navigate through paths manually
        update_service_uri = _redfishobj.root.obj['UpdateService']['@odata.id']
    else:
        #obtain all account instances from resource directory
        for instance in resource_instances:
            if '#UpdateService.' in instance['@odata.type']:
                update_service_uri = instance['@odata.id']

    update_service_response = _redfishobj.get(update_service_uri)

    path = update_service_response.obj.HttpPushUri

    body = []
    json_data = {'UpdateRepository': update_repo, 'UpdateTarget': update_target, 'ETag': 'atag', 'Section': 0}
    session_key = _redfishobj.session_key

    filename = os.path.basename(firmware_loc)
    with open(firmware_loc, 'rb') as fle:
        filenameOutput = fle.read()

    filename = os.path.basename(compsig_loc)
    with open(compsig_loc, 'rb') as fle:
        compsigOutput = fle.read()

    session_tuple = ('sessionKey', session_key)
    parameters_tuple = ('parameters', json.dumps(json_data))
    file_tuple = ('file', (filename, filenameOutput, 'application/octet-stream'))
    comp_tuple = ('compsig', (filename, compsigOutput, 'application/octet-stream'))

    #Build the payload from each multipart-form data tuple
    body.append(session_tuple)
    body.append(parameters_tuple)
    body.append(comp_tuple)
    body.append(file_tuple)

    #Create our header dictionary
    header = {'Cookie': 'sessionKey=' + session_key}

    #We pass the whole list payload to post
    resp = _redfishobj.post(path, body, headers=header)

    if resp.status == 400:
        sys.stderr.write("Failed to upload firmware...")
    elif not resp.status in [200, 201]:
        sys.stderr.write("An http response of '%s' was returned.\n" % resp.status)
    else:
        print("Upload complete!\n")

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.0"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://10.0.0.0"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    # The path to the firmware file to upload
    FIRMWARE_PATH = "/path/to/component.exe"
    COMPSIG_PATH = "/path/to/component.compsiq"
    # Upload the firmware file to the iLO Repository
    UPDATE_REPO = True
    # Update the system with the firmware file
    UPDATE_TARGET = False

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = True

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    upload_firmware(REDFISHOBJ, FIRMWARE_PATH, COMPSIG_PATH, UPDATE_REPO, UPDATE_TARGET)

    REDFISHOBJ.logout()
