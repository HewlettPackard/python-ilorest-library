import sys
from Redfish._redfishobject import RedfishObject

# When running on the server locally use the following commented values
# iLO_host = "blobstore://."
# iLO_account = "None"
# iLO_password = "None"

# When running remotely connect using the iLO address, iLO account name, 
# and password to send https requests
iLO_https_url = "https://10.0.0.100"
iLO_account = "admin"
iLO_password = "password"

## Create a REDFISH object
REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)

# Do a GET on a given path
response = REDFISH_OBJ.redfish_get('/rest/v1/systems/1')

# Print out the response
sys.stdout.write("%s\n" % response)

# Logout of the current session
REDFISH_OBJ.redfish_client.logout()