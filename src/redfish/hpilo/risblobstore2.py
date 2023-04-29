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
"""Base implementation for interaction with blob store interface"""

# ---------Imports---------

import os
import sys
import struct
import random
import string
import logging

from ctypes import (
    c_char_p,
    c_ubyte,
    c_uint,
    cdll,
    POINTER,
    create_string_buffer,
    c_ushort,
    c_void_p,
)

from redfish.hpilo.rishpilo import HpIlo, HpIloInitialError, HpIloChifPacketExchangeError
from redfish.hpilo.rishpilo import BlobReturnCodes as hpiloreturncodes

if os.name == "nt":
    from ctypes import windll
else:
    from _ctypes import dlclose

# ---------End of imports---------
# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------
# -----------------------Error Returns----------------------


class UnexpectedResponseError(Exception):
    """Raise when we get data that we don't expect from iLO"""

    pass


class HpIloError(Exception):
    """Raised when iLO returns non-zero error code"""

    pass


class Blob2CreateError(Exception):
    """Raised when create operation fails"""

    pass


class Blob2InfoError(Exception):
    """Raised when create operation fails"""

    pass


class Blob2ReadError(Exception):
    """Raised when read operation fails"""

    pass


class Blob2WriteError(Exception):
    """Raised when write operation fails"""

    pass


class Blob2DeleteError(Exception):
    """Raised when delete operation fails"""

    pass


class Blob2OverrideError(Exception):
    """Raised when delete operation fails because of it been overwritten"""

    pass


class BlobRetriesExhaustedError(Exception):
    """Raised when max retries have been attempted for same operation"""

    pass


class Blob2FinalizeError(Exception):
    """Raised when finalize operation fails"""

    pass


class Blob2ListError(Exception):
    """Raised when list operation fails"""

    pass


class Blob2SecurityError(Exception):
    """Raised when there is an issue with security"""

    pass


class BlobNotFoundError(Exception):
    """Raised when blob not found in key/namespace"""

    pass


class ChifDllMissingError(Exception):
    """Raised when unable to obtain ilorest_chif dll handle"""

    pass


class EncryptionEnabledError(Exception):
    """Raised when high security encryption is enabled"""

    pass


# ----------------------------------------------------------

# -------------------Helper functions-------------------------


class BlobReturnCodes(object):
    """Blob store return codes.

    SUCCESS           success
    BADPARAMETER      bad parameter supplied
    NOTFOUND          blob name not found
    NOTMODIFIED       call did not perform the operation

    """

    SUCCESS = 0
    BADPARAMETER = 2
    NOTFOUND = 12
    NOTMODIFIED = 20


class BlobStore2(object):
    """Blob store 2 class"""

    def __init__(self):
        lib = self.gethprestchifhandle()
        self.channel = HpIlo(dll=lib)
        self.max_retries = 3

    def __del__(self):
        """Blob store 2 close channel function"""
        if hasattr(self, "channel"):
            self.channel.close()

    def create(self, key, namespace):
        """Create the blob

        :param key: The blob key to create.
        :type key: str.
        :param namespace: The blob namespace to create the key in.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.create_not_blobentry.argtypes = [c_char_p, c_char_p]
        lib.create_not_blobentry.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.create_not_blobentry(name, namespace)
        data = ptr[: lib.size_of_createRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def get_info(self, key, namespace, retries=0):
        """Get information for a particular blob

        :param key: The blob key to retrieve.
        :type key: str.
        :param namespace: The blob namespace to retrieve the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.get_info.argtypes = [c_char_p, c_char_p]
        lib.get_info.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namspace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.get_info(name, namspace)
        data = ptr[: lib.size_of_infoRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if errorcode == BlobReturnCodes.BADPARAMETER:
            if retries < self.max_retries:
                self.get_info(key=key, namespace=namespace, retries=retries + 1)
            else:
                raise Blob2OverrideError(errorcode)
        elif errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(key, namespace)

        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        response = resp[lib.size_of_responseHeaderBlob() :]

        self.unloadchifhandle(lib)

        return response

    def read(self, key, namespace, retries=0):
        """Read a particular blob

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        maxread = lib.max_read_size()
        readsize = lib.size_of_readRequest()
        readhead = lib.size_of_responseHeaderBlob()

        self.unloadchifhandle(lib)

        blob_info = self.get_info(key, namespace)
        blobsize = struct.unpack("<I", bytes(blob_info[0:4]))[0]

        bytes_read = 0
        data = bytearray()

        while bytes_read < blobsize:
            if (maxread - readsize) < (blobsize - bytes_read):
                count = maxread - readsize
            else:
                count = blobsize - bytes_read

            read_block_size = bytes_read
            recvpkt = self.read_fragment(key, namespace, read_block_size, count)

            newreadsize = readhead + 4
            bytesread = struct.unpack("<I", bytes(recvpkt[readhead:(newreadsize)]))[0]

            if bytesread == 0:
                if retries < self.max_retries:
                    data = self.read(key=key, namespace=namespace, retries=retries + 1)
                    return data
                else:
                    raise BlobRetriesExhaustedError()

            data.extend(recvpkt[newreadsize : newreadsize + bytesread])
            bytes_read += bytesread

        return data

    def read_fragment(self, key, namespace, offset=0, count=1):
        """Fragmented version of read function for large blobs

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.
        :param offset: The data offset for the current fragmented read.
        :type key: int.
        :param count: The data count for the current fragmented read.
        :type namespace: int.

        """
        lib = self.gethprestchifhandle()
        lib.read_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.read_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.read_fragment(offset, count, name, namespace)
        data = ptr[: lib.size_of_readRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        resp = resp + b"\0" * (lib.size_of_readResponse() - len(resp))

        return resp

    def write(self, key, namespace, data=None):
        """Write a particular blob

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written.
        :type data: str.

        """
        lib = self.gethprestchifhandle()
        maxwrite = lib.max_write_size()
        writesize = lib.size_of_writeRequest()

        self.unloadchifhandle(lib)

        if data:
            data_length = len(data)
            bytes_written = 0

            while bytes_written < data_length:
                if (maxwrite - writesize) < (data_length - bytes_written):
                    count = maxwrite - writesize
                else:
                    count = data_length - bytes_written

                write_blob_size = bytes_written

                self.write_fragment(
                    key,
                    namespace=namespace,
                    data=data[write_blob_size : write_blob_size + count],
                    offset=write_blob_size,
                    count=count,
                )

                bytes_written += count

        return self.finalize(key, namespace=namespace)

    def write_fragment(self, key, namespace, data=None, offset=0, count=1):
        """Fragmented version of write function for large blobs

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written to blob.
        :type data: str.
        :param offset: The data offset for the current fragmented write.
        :type key: int.
        :param count: The data count for the current fragmented write.
        :type count: int.

        """
        lib = self.gethprestchifhandle()
        lib.write_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.write_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.write_fragment(offset, count, name, namespace)
        sendpacket = ptr[: lib.size_of_writeRequest()]

        if isinstance(data, str):
            data = data.encode("utf-8")

        dataarr = bytearray(sendpacket)
        dataarr.extend(memoryview(data))

        resp = self._send_receive_raw(dataarr)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def delete(self, key, namespace, retries=0):
        """Delete the blob

        :param key: The blob key to be deleted.
        :type key: str.
        :param namespace: The blob namespace to delete the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.delete_blob.argtypes = [c_char_p, c_char_p]
        lib.delete_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namspace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.delete_blob(name, namspace)
        data = ptr[: lib.size_of_deleteRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if errorcode == BlobReturnCodes.BADPARAMETER:
            if retries < self.max_retries:
                self.delete(key=key, namespace=namespace, retries=retries + 1)
            else:
                raise Blob2OverrideError(errorcode)
        elif not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return errorcode

    def list(self, namespace):
        """List operation to retrieve all blobs in a given namespace

        :param namespace: The blob namespace to retrieve the keys from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.list_blob.argtypes = [c_char_p]
        lib.list_blob.restype = POINTER(c_ubyte)

        namespace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.list_blob(namespace)
        data = ptr[: lib.size_of_listRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        resp = resp + b"\0" * (lib.size_of_listResponse() - len(resp))

        self.unloadchifhandle(lib)

        return resp

    def finalize(self, key, namespace):
        """Finalize the blob

        :param key: The blob key to be finalized.
        :type key: str.
        :param namespace: The blob namespace to finalize the key in.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.finalize_blob.argtypes = [c_char_p, c_char_p]
        lib.finalize_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.finalize_blob(name, namespace)
        data = ptr[: lib.size_of_finalizeRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return errorcode

    def rest_immediate(
        self,
        req_data,
        rqt_key="RisRequest",
        rsp_key="RisResponse",
        rsp_namespace="volatile",
    ):
        """Read/write blob via immediate operation

        :param req_data: The blob data to be read/written.
        :type req_data: str.
        :param rqt_key: The blob key to be used for the request data.
        :type rqt_key: str.
        :param rsp_key: The blob key to be used for the response data.
        :type rsp_key: str.
        :param rsp_namespace: The blob namespace to retrieve the response from.
        :type rsp_namespace: str.

        """
        rqt_key = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
        rsp_key = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )

        lib = self.gethprestchifhandle()

        if len(req_data) < (lib.size_of_restImmediateRequest() + lib.max_write_size()):
            lib.rest_immediate.argtypes = [c_uint, c_char_p, c_char_p]
            lib.rest_immediate.restype = POINTER(c_ubyte)

            name = create_string_buffer(rsp_key.encode("utf-8"))
            namespace = create_string_buffer(rsp_namespace.encode("utf-8"))

            ptr = lib.rest_immediate(len(req_data), name, namespace)
            sendpacket = ptr[: lib.size_of_restImmediateRequest()]
            mode = False
        else:
            self.create(rqt_key, rsp_namespace)
            self.write(rqt_key, rsp_namespace, req_data)

            lib.rest_immediate_blobdesc.argtypes = [c_char_p, c_char_p, c_char_p]
            lib.rest_immediate_blobdesc.restype = POINTER(c_ubyte)

            name = create_string_buffer(rqt_key.encode("utf-8"))
            namespace = create_string_buffer(rsp_namespace.encode("utf-8"))
            rspname = create_string_buffer(rsp_key.encode("utf-8"))

            ptr = lib.rest_immediate_blobdesc(name, rspname, namespace)
            sendpacket = ptr[: lib.size_of_restBlobRequest()]
            mode = True

        data = bytearray(sendpacket)

        if not mode:
            data.extend(req_data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(rsp_key, rsp_namespace)

        recvmode = struct.unpack("<I", bytes(resp[12:16]))[0]

        fixdlen = lib.size_of_restResponseFixed()
        response = resp[fixdlen : struct.unpack("<I", bytes(resp[16:20]))[0] + fixdlen]

        tmpresponse = None
        if errorcode == BlobReturnCodes.SUCCESS and not mode:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
        elif errorcode == BlobReturnCodes.NOTMODIFIED and not mode:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
        elif errorcode == BlobReturnCodes.SUCCESS:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
        elif recvmode == 0:
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        if not tmpresponse and recvmode == 1:
            tmpresponse = self.read(rsp_key, rsp_namespace)

            try:
                self.delete(rsp_key, rsp_namespace)
            except Exception as excp:
                raise excp
        else:
            try:
                self.delete(rsp_key, rsp_namespace)
            except Blob2OverrideError as excp:
                pass
            except HpIloChifPacketExchangeError as excp:
                pass
            except Exception as excp:
                raise excp

        return tmpresponse

    def get_security_state(self):
        """Get information for the current security state"""
        lib = self.gethprestchifhandle()
        lib.get_security_state.argtypes = []
        lib.get_security_state.restype = POINTER(c_ubyte)

        ptr = lib.get_security_state()
        data = ptr[: lib.size_of_securityStateRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        try:
            securitystate = struct.unpack("<c", bytes(resp[72]))[0]
        except:
            securitystate = int(resp[72])

        self.unloadchifhandle(lib)

        return securitystate

    def mount_blackbox(self):
        """Operation to mount the blackbox partition"""
        lib = self.gethprestchifhandle()
        lib.blackbox_media_mount.argtypes = []
        lib.blackbox_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.blackbox_media_mount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def absaroka_media_mount(self):
        """Operation to mount the absaroka repo partition"""
        lib = self.gethprestchifhandle()
        lib.absaroka_media_mount.argtypes = []
        lib.absaroka_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.absaroka_media_mount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def gaius_media_mount(self):
        """Operation to mount the gaius media partition"""
        lib = self.gethprestchifhandle()
        lib.gaius_media_mount.argtypes = []
        lib.gaius_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.gaius_media_mount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def vid_media_mount(self):
        """Operation to mount the gaius media partition"""
        lib = self.gethprestchifhandle()
        lib.vid_media_mount.argtypes = []
        lib.vid_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.vid_media_mount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def mountflat(self):
        """Operation to mount the gaius media partition"""
        lib = self.gethprestchifhandle()
        lib.flat_media_mount.argtypes = []
        lib.flat_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.flat_media_mount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.media_unmount.argtypes = []
        lib.media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.media_unmount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def bb_media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.bb_media_unmount.argtypes = []
        lib.bb_media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.bb_media_unmount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def vid_media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.vid_media_unmount.argtypes = []
        lib.vid_media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.vid_media_unmount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def gaius_media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.gaius_media_unmount.argtypes = []
        lib.gaius_media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.gaius_media_unmount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def absr_media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.absaroka_media_unmount.argtypes = []
        lib.absaroka_media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.absaroka_media_unmount()
        data = ptr[: lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data)

        errorcode = resp[12]
        if not (
            errorcode == BlobReturnCodes.SUCCESS
            or errorcode == BlobReturnCodes.NOTMODIFIED
        ):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def _send_receive_raw(self, indata):
        """Send and receive raw function for blob operations

        :param indata: The data to be sent to blob operation.
        :type indata: str.

        """
        excp = None
        for _ in range(0, 3):  # channel loop for iLO
            try:
                resp = self.channel.send_receive_raw(indata, 10)
                return resp
            except Exception as exp:
                self.channel.close()
                lib = self.gethprestchifhandle()
                self.channel = HpIlo(dll=lib)
                excp = exp
        if excp:
            raise excp

    def cert_login(self, cert_file, priv_key, key_pass):
        lib = self.gethprestchifhandle()
        lib.login_cert.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        lib.login_cert.restype = c_char_p

        token = lib.login_cert(self.channel.fhandle, cert_file, priv_key, key_pass)
        return token

    @staticmethod
    def gethprestchifhandle():
        """Multi platform handle for chif hprest library"""
        excp = None
        libhandle = None
        if os.name != "nt":
            libpath = '/opt/ilorest/lib64/libilorestchif.so'
            if os.path.isfile(libpath):
                libhandle = cdll.LoadLibrary(libpath)
        if not libhandle:
            libnames = (
                ["ilorest_chif.dll", "hprest_chif.dll"]
                if os.name == "nt"
                else [
                    "ilorest_chif_dev.so",
                    "hprest_chif_dev.so",
                    "ilorest_chif.so",
                    "hprest_chif.so",
                ]
            )
            for libname in libnames:
                try:
                    libpath = BlobStore2.checkincurrdirectory(libname)
                    LOGGER.info("Loading Library %s for libhpsrv", libpath)
                    libhandle = cdll.LoadLibrary(libpath)
                    if libhandle:
                        LOGGER.info("Got Libhandle %s for libhpsrv", libhandle)
                        break
                except Exception as exp:
                    excp = exp

        if libhandle:
            BlobStore2.setglobalhprestchifrandnumber(libhandle)
            return libhandle
        raise ChifDllMissingError(excp)

    @staticmethod
    def setglobalhprestchifrandnumber(libbhndl):
        """Set the random number for the chif handle
        :param libbhndl: The library handle provided by loading the chif library.
        :type libbhndl: library handle.
        """
        rndval = random.randint(1, 65535)
        libbhndl.updaterandval.argtypes = [c_ushort]
        libbhndl.updaterandval(rndval)

    @staticmethod
    def initializecreds(username=None, password=None):
        """Get chif ready to use high security
        :param username: The username to login.
        :type username: str.
        :param password: The password to login.
        :type password: str.
        """
        LOGGER.info("Inside initializecreds")
        dll = BlobStore2.gethprestchifhandle()
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.info("Enabling DEBUG from libhpsrv")
            dll.enabledebugoutput()
        LOGGER.info("Calling ChifInitialize from libhpsrv")
        dll.ChifInitialize(None)
        if username:
            if not password:
                return False
            if dll.ChifIsSecurityRequired() > 0:
                dll.initiate_credentials.argtypes = [c_char_p, c_char_p]
                dll.initiate_credentials.restype = POINTER(c_ubyte)

                usernew = create_string_buffer(username.encode("utf-8"))
                passnew = create_string_buffer(password.encode("utf-8"))

                LOGGER.info("Calling initiate_credentials from libhpsrv")
                dll.initiate_credentials(usernew, passnew)
                LOGGER.info("Calling ChifVerifyCredentials from libhpsrv")
                credreturn = dll.ChifVerifyCredentials()
                if not credreturn == BlobReturnCodes.SUCCESS:
                    if credreturn == hpiloreturncodes.CHIFERR_AccessDenied:
                        raise Blob2SecurityError()
                    else:
                        raise HpIloInitialError(
                            "Error %s occurred while trying "
                            "to open a channel to iLO" % credreturn
                        )
            else:
                dll.ChifDisableSecurity()
        else:
            # if high security return False
            LOGGER.info("Calling ChifIsSecurityRequired from libhpsrv")
            if dll.ChifIsSecurityRequired() > 0:
                return False
            else:
                LOGGER.info("Calling ChifDisableSecurity from libhpsrv")
                dll.ChifDisableSecurity()

        BlobStore2.unloadchifhandle(dll)

        return True

    @staticmethod
    def checkincurrdirectory(libname):
        """Check if the library is present in current directory.
        :param libname: The name of the library to search for.
        :type libname: str."""
        libpath = libname

        if os.path.isfile(os.path.join(os.path.split(sys.executable)[0], libpath)):
            libpath = os.path.join(os.path.split(sys.executable)[0], libpath)
        elif os.path.isfile(os.path.join(os.getcwd(), libpath)):
            libpath = os.path.join(os.getcwd(), libpath)
        elif os.environ.get("LD_LIBRARY_PATH"):
            paths = os.getenv("LD_LIBRARY_PATH", libpath).split(";")
            libpath = [
                os.path.join(pat, libname)
                for pat in paths
                if os.path.isfile(os.path.join(pat, libname))
            ]
            libpath = libpath[0] if libpath else libname

        return libpath

    @staticmethod
    def unloadchifhandle(lib):
        """Release a handle on the chif iLOrest library

        :param lib: The library handle provided by loading the chif library.
        :type lib: library handle.

        """
        try:
            libhandle = lib._handle
            if os.name == "nt":
                windll.kernel32.FreeLibrary(None, handle=libhandle)
            else:
                dlclose(libhandle)
        except Exception:
            pass
