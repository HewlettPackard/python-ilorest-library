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
An example of manually managing sessions with Redfish
"""

import sys
import json
import urllib.parse
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

def sessions(_redfishobj, login_account, login_password):

    new_session = {"UserName": login_account, "Password": login_password}
    response = _redfishobj.post('/redfish/v1/Sessions', new_session)

    if response.status == 201:
        print("Success!\n")
        session_uri = response.getheader("location")
        session_uri = urllib.parse.urlparse(session_uri)
        sys.stdout.write("\tSession " + session_uri.path + " created.\n")
        x_auth_token = response.getheader("x-auth-token")
        sys.stdout.write("\tThis is the session X-Auth Token key " + x_auth_token + ".\n")
        print(json.dumps(response.dict, indent=4, sort_keys=True))

        # Delete the created session
        sys.stdout.write("\tTerminating this session.\n")
        sessresp = _redfishobj.delete(session_uri.path)
        print(json.dumps(sessresp.dict, indent=4, sort_keys=True))
    else:
        sys.stderr.write("ERROR: failed to create a session.\n")
        try:
            print(json.dumps(sessresp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                            sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended"
                             " Message Info...")

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://10.0.0.100"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    sessions(REDFISHOBJ, LOGIN_ACCOUNT, LOGIN_PASSWORD)
