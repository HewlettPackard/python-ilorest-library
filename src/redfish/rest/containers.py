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
"""Containers used for REST requests and responses."""
import json
import sys

try:
    from collections import OrderedDict
except ImportError:
    from collections.abc import OrderedDict

from six import BytesIO, StringIO, string_types, text_type
from six.moves import http_client
from urllib3.util import Timeout, Retry


class JSONEncoder(json.JSONEncoder):
    """JSON Encoder class"""

    def default(self, obj):
        """Set defaults in JSON encoder class

        :param obj: object to be encoded into JSON.
        :type obj: RestResponse
        :returns: A JSON :class:`OrderedDict`
        """
        if isinstance(obj, RestResponse):
            jsondict = OrderedDict()
            jsondict["Status"] = obj.status
            jsondict["Headers"] = obj.getheaders()

            if obj.read:
                jsondict["Content"] = obj.dict

            return jsondict
        if isinstance(obj, bytes):
            obj = obj.decode("utf-8")
        if isinstance(obj, Timeout):
            jsondict = OrderedDict()
            jsondict["connect_timeout"] = obj.connect_timeout
            jsondict["read_timeout"] = obj.read_timeout
            return jsondict
        if isinstance(obj, Retry):
            jsondict = OrderedDict()
            jsondict["connect"] = obj.connect
            jsondict["read"] = obj.read
            jsondict["redirect"] = obj.redirect
            return jsondict
        return json.JSONEncoder.default(self, obj)


class JSONDecoder(json.JSONDecoder):
    """Custom JSONDecoder that understands our types"""

    def decode(self, json_string):
        """Decode JSON string

        :param json_string: The JSON string to be decoded into usable data.
        :type json_string: str
        :returns: returns a parsed dict
        """
        parsed_dict = super(JSONDecoder, self).decode(json_string)
        return parsed_dict


class _FakeSocket(BytesIO):
    """slick way to parse a http response.
    http://pythonwise.blogspot.com/2010/02/parse-http-response.html"""

    def makefile(self, *args, **kwargs):
        """Return self object"""
        return self


class RisObject(dict):
    """Converts a JSON/Rest dict into a object so you can use .property notation

    :param d: dictionary to be converted
    :type d: dict
    """

    __getattr__ = dict.__getitem__

    def __init__(self, d):
        """Initialize RisObject"""
        super(RisObject, self).__init__()
        self.update(**dict((k, self.parse(value)) for k, value in list(d.items())))

    @classmethod
    def parse(cls, value):
        """Parse for RIS value

        :param cls: class referenced from class method
        :type cls: RisObject
        :param value: value to be parsed
        :type value: data type
        :returns: returns parsed value
        """
        if isinstance(value, dict):
            return cls(value)
        elif isinstance(value, list):
            return [cls.parse(i) for i in value]

        return value


class RestRequest(object):
    """Holder for Request information

    :param path: The URI path.
    :type path: str
    :param method: method to be implemented
    :type method: str
    :param data: body payload for the rest call
    :type data: dict
    """

    def __init__(self, path, method="GET", data="", url=None):
        self._path = path
        self._body = data
        self._method = method
        self.url = url

    @property
    def path(self):
        """The path the request is made against."""
        return self._path

    @property
    def method(self):
        """The method to implement."""
        return self._method

    @property
    def body(self):
        """The body to pass along with the request, if any."""
        return self._body

    def __str__(self):
        """Format string"""
        body = "" if not self._body else self._body
        try:
            return "{} {}\n\n{}".format(self.method, self.path, body)
        except:
            return "{} {}\n\n{}".format(self.method, self.path, "")


class RestResponse(object):
    """Returned by Rest requests

    :param rest_request: Holder for request information
    :type rest_request: :class:`RestRequest` object
    :param http_response: Response from HTTP
    :type http_response: :class:`HTTPResponse` object
    """

    def __init__(self, rest_request, http_response):
        self._read = None
        self._status = None
        self._headers = None
        self._session_key = None
        self._session_location = None
        self._rest_request = rest_request
        self._http_response = http_response
        self._read = self._http_response.data if http_response is not None else None
        self._ori = self._read

    @property
    def read(self):
        """The response body, attempted to be translated into json, else is a string."""
        if self._read and not isinstance(self._read, text_type):
            self._read = self._read.decode("utf-8", "ignore")
        return self._read

    @read.setter
    def read(self, read):
        """Property for setting _read

        :param read: The data to set to read.
        :type read: str
        """
        if read is not None:
            if isinstance(read, dict):
                read = json.dumps(read, indent=4)
            self._read = read

    def getheaders(self):
        """Get all headers included in the response."""
        return dict(self._http_response.headers) if self._http_response is not None else self._headers

    def getheader(self, name):
        """Case-insensitive search for an individual header

        :param name: The header name to retrieve.
        :type name: str
        :returns: returns a header from HTTP response or None if not found.
        """

        def search_dict(search_key, dct):
            for key, val in dct.items():
                if key.lower() == search_key.lower():
                    return val
            return None

        if self._http_response:
            return search_dict(name, self._http_response.headers)
        return search_dict(name, self._headers)

    def loaddict(self, newdict):
        """Property for setting JSON data. Used during initialization.

        :param newdict: The string data to set as JSON data.
        :type newdict: str
        """
        self._read = json.dumps(newdict, indent=4)

    @property
    def dict(self):
        """The response body data as an dict"""
        try:
            return json.loads(self.read)
        except ValueError as exp:
            if self.path != "/smbios" and self.path != "/cgi-bin/uploadFile" and "/redfish/v1/Systems/1/Storage/" not in self.path :
                sys.stderr.write("An invalid response body was returned: %s" % exp)
            return None

    @property
    def obj(self):
        """The response body data as an object"""
        return RisObject.parse(self.dict)

    @property
    def ori(self):
        """The original response body data"""
        return self._ori

    @property
    def status(self):
        """The status code of the request."""
        if self._status:
            return self._status

        return self._http_response.status if self._http_response is not None else self._status

    @property
    def session_key(self):
        """The saved session key for the connection."""
        if self._session_key:
            return self._session_key

        self._session_key = self.getheader("x-auth-token")
        return self._session_key

    @property
    def session_location(self):
        """The saved session location, used for logging out."""
        if self._session_location:
            return self._session_location

        self._session_location = self.getheader("location")
        return self._session_location

    @property
    def request(self):
        """The saved http request the response was generated by."""
        return self._rest_request

    @property
    def path(self):
        """The path the request was made against."""
        return self.request.path

    def __str__(self):
        """Class string formatter"""
        headerstr = ""
        for kiy, val in self.getheaders().items():
            headerstr += "%s %s\n" % (kiy, val)

        return "%(status)s\n%(headerstr)s\n\n%(body)s" % {
            "status": self.status,
            "headerstr": headerstr,
            "body": self.read,
        }


class RisRestResponse(RestResponse):
    """Returned by Rest requests from CHIF

    :param rest_request: Holder for request information
    :type rest_request: :class:`RestRequest` object
    :param resp_text: text from response to be buffered and read
    :type resp_text: str
    """

    def __init__(self, rest_request, resp_txt):
        """Initialization of RisRestResponse"""
        if not isinstance(resp_txt, string_types):
            resp_txt = "".join(map(chr, resp_txt))
        self._respfh = StringIO(resp_txt)
        self._socket = _FakeSocket(bytearray(list(map(ord, self._respfh.read()))))
        #self._respfh = BytesIO(resp_txt.encode('utf-8'))
        #self._socket = _FakeSocket(bytearray(self._respfh.read()))

        response = http_client.HTTPResponse(self._socket)
        #response = response.decode('utf-8')
        response.begin()
        response.data = response.read()
        response.headers = {ki[0]: ki[1] for ki in response.getheaders()}
        super(RisRestResponse, self).__init__(rest_request, response)


class StaticRestResponse(RestResponse):
    """A RestResponse object used when data is being cached."""

    def __init__(self, **kwargs):
        restreq = None

        if "restreq" in kwargs:
            restreq = kwargs["restreq"]

        super(StaticRestResponse, self).__init__(restreq, None)

        if "Status" in kwargs:
            self._status = kwargs["Status"]

        if "Headers" in kwargs:
            self._headers = kwargs["Headers"]

        if "session_key" in kwargs:
            self._session_key = kwargs["session_key"]

        if "session_location" in kwargs:
            self._session_location = kwargs["session_location"]

        if "Content" in kwargs:
            content = kwargs["Content"]

            if isinstance(content, string_types):
                self._read = content
            else:
                self._read = json.dumps(content)
        else:
            self._read = ""

    def getheaders(self):
        """Function for accessing the headers"""
        returnlist = {}

        if isinstance(self._headers, dict):
            returnlist = self._headers
        elif isinstance(self._headers, (list, tuple)):
            returnlist = {ki[0]: ki[1] for ki in self._headers}
        else:
            for item in self._headers:
                returnlist.update(item.items()[0])

        return returnlist
