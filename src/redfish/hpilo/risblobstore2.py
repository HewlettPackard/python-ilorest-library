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

import logging
import random
import struct
import string
import sys
import time
import os
from ctypes import POINTER, c_char_p, c_ubyte, c_uint, c_ushort, c_void_p, cdll, create_string_buffer

from redfish.hpilo.rishpilo import BlobReturnCodes as hpiloreturncodes
from redfish.hpilo.rishpilo import (
    HpIlo,
    HpIloChifPacketExchangeError,
    HpIloInitialError,
)

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

    def __init__(self, log_dir=None):
        lib = self.gethprestchifhandle()
        self.log_dir = log_dir
        self.channel = HpIlo(dll=lib, log_dir=log_dir)
        self.max_retries = 44
        self.max_read_retries = 3
        self.delay = 0.25

        LOGGER.info("BlobStore initialized with log directory: %s", log_dir)

    def __del__(self):
        """Blob store 2 close channel function"""
        if hasattr(self, "channel"):
            LOGGER.info("Closing BlobStore channel.")
            self.channel.close()

    def create(self, key, namespace):
        """
        Create the blob.

        :param key: The blob key to create.
        :type key: str
        :param namespace: The blob namespace to create the key in.
        :type namespace: str
        :return: The response from the blob creation request.
        :rtype: bytearray
        :raises HpIloError: If the operation fails.
        """
        LOGGER.info("Attempting to create blob: Key=%s, Namespace=%s", key, namespace)

        try:
            lib = self.gethprestchifhandle()
            lib.create_not_blobentry.argtypes = [c_char_p, c_char_p]
            lib.create_not_blobentry.restype = POINTER(c_ubyte)

            name = create_string_buffer(key.encode("utf-8"))
            namespace = create_string_buffer(namespace.encode("utf-8"))

            LOGGER.debug("Calling create_not_blobentry()")
            ptr = lib.create_not_blobentry(name, namespace)

            LOGGER.debug("Preparing request data")
            data = ptr[: lib.size_of_createRequest()]
            data = bytearray(data)

            LOGGER.info("Sending blob creation request")
            resp = self._send_receive_raw(data)

            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
                LOGGER.error("Blob creation failed. Error Code: %d", errorcode)
                raise HpIloError(errorcode)

            LOGGER.info("Blob creation successful for Key=%s, Namespace=%s", key, namespace)
            return resp

        except Exception as e:
            LOGGER.exception("Exception during blob creation: %s", str(e))
            raise

        finally:
            LOGGER.debug("Unloading library handle")
            self.unloadchifhandle(lib)

    def get_info(self, key, namespace, retries=0):
        """Get information for a particular blob.

        :param key: The blob key to retrieve.
        :type key: str.
        :param namespace: The blob namespace to retrieve the key from.
        :type namespace: str.

        """
        LOGGER.info(f"get_info called with key='{key}', namespace='{namespace}', retries={retries}")

        lib = self.gethprestchifhandle()
        lib.get_info.argtypes = [c_char_p, c_char_p]
        lib.get_info.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namspace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.get_info(name, namspace)
        data = ptr[: lib.size_of_infoRequest()]
        data = bytearray(data)

        while retries <= self.max_retries:
            LOGGER.debug(f"Attempt {retries+1}/{self.max_retries} - Sending request to iLO.")

            resp = self._send_receive_raw(data)
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]

            LOGGER.debug(f"Response received: errorcode={errorcode}")

            if errorcode == BlobReturnCodes.BADPARAMETER:
                if retries < self.max_retries:
                    LOGGER.warning(
                        f"BADPARAMETER error received. Retrying in {self.delay} seconds... ({retries+1}/{self.max_retries})"
                    )
                    time.sleep(self.delay)
                    retries += 1
                    self.delay += 0.05
                else:
                    LOGGER.error(f"Max retries ({self.max_retries}) exceeded. Raising Blob2OverrideError.")
                    raise Blob2OverrideError(errorcode)

            elif errorcode == BlobReturnCodes.NOTFOUND:
                LOGGER.error(f"BlobNotFoundError: key='{key}', namespace='{namespace}'")
                raise BlobNotFoundError(key, namespace)

            elif errorcode not in (BlobReturnCodes.SUCCESS, BlobReturnCodes.NOTMODIFIED):
                LOGGER.error(f"HpIloError: Unexpected error code {errorcode}.")
                raise HpIloError(errorcode)

            else:
                LOGGER.info(f"Request successful. Extracting response data.")
                break

        response = resp[lib.size_of_responseHeaderBlob() :]
        self.unloadchifhandle(lib)

        LOGGER.info(f"get_info completed successfully for key='{key}', namespace='{namespace}'.")
        return response

    def read(self, key, namespace, retries=0):
        """Read a particular blob

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.

        """
        LOGGER.info("Starting blob read: Key=%s, Namespace=%s, Retry=%d", key, namespace, retries)

        try:
            lib = self.gethprestchifhandle()
            maxread = lib.max_read_size()
            readsize = lib.size_of_readRequest()
            readhead = lib.size_of_responseHeaderBlob()
            self.unloadchifhandle(lib)

            # Get blob metadata
            LOGGER.debug("Fetching blob info to determine size.")
            blob_info = self.get_info(key, namespace)
            blobsize = struct.unpack("<I", bytes(blob_info[0:4]))[0]
            LOGGER.info("Blob size determined: %d bytes", blobsize)

            bytes_read = 0
            data = bytearray()

            while bytes_read < blobsize:
                count = min(maxread - readsize, blobsize - bytes_read)

                LOGGER.debug("Reading fragment: Offset=%d, Size=%d", bytes_read, count)
                recvpkt = self.read_fragment(key, namespace, bytes_read, count)

                newreadsize = readhead + 4
                bytesread = struct.unpack("<I", bytes(recvpkt[readhead:newreadsize]))[0]
                LOGGER.debug("Bytes read in current fragment: %d", bytesread)

                if bytesread == 0:
                    if retries < self.max_read_retries:
                        LOGGER.warning(
                            "Read attempt failed. Retrying (Attempt %d/%d).", retries + 1, self.max_read_retries
                        )
                        return self.read(key=key, namespace=namespace, retries=retries + 1)
                    else:
                        LOGGER.error("Maximum read retries (%d) exceeded.", self.max_read_retries)
                        raise BlobRetriesExhaustedError()

                data.extend(recvpkt[newreadsize : newreadsize + bytesread])
                bytes_read += bytesread
                LOGGER.debug("Total bytes read so far: %d/%d", bytes_read, blobsize)

            LOGGER.info("Blob read successfully: Key=%s, Namespace=%s, Total Bytes=%d", key, namespace, len(data))
            return data

        except Exception as e:
            LOGGER.exception("Error during blob read: %s", str(e))
            raise

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
        LOGGER.info(
            "Starting fragmented blob read: Key=%s, Namespace=%s, Offset=%d, Count=%d", key, namespace, offset, count
        )

        try:
            lib = self.gethprestchifhandle()
            lib.read_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
            lib.read_fragment.restype = POINTER(c_ubyte)

            name = create_string_buffer(key.encode("utf-8"))
            namespace_buf = create_string_buffer(namespace.encode("utf-8"))

            LOGGER.debug("Preparing request data for read_fragment.")
            ptr = lib.read_fragment(offset, count, name, namespace_buf)

            request_size = lib.size_of_readRequest()
            response_size = lib.size_of_readResponse()

            LOGGER.debug("Extracting request data (Size=%d)", request_size)
            data = bytearray(ptr[:request_size])

            LOGGER.info("Sending fragmented read request to iLO.")
            resp = self._send_receive_raw(data)

            if len(resp) < response_size:
                LOGGER.warning("Received response smaller than expected. Padding response.")
                resp = resp + b"\0" * (response_size - len(resp))

            LOGGER.info("Fragmented blob read successful: Key=%s, Bytes Received=%d", key, len(resp))
            return resp

        except Exception as e:
            LOGGER.exception("Error occurred during read_fragment: %s", str(e))
            raise

    def write(self, key, namespace, data=None):
        """Write a particular blob

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written.
        :type data: str.

        """
        LOGGER.info(f"Starting to write blob with key: {key} in namespace: {namespace}")

        lib = self.gethprestchifhandle()
        maxwrite = lib.max_write_size()
        writesize = lib.size_of_writeRequest()

        LOGGER.debug(f"Max write size: {maxwrite}, Write request size: {writesize}")

        self.unloadchifhandle(lib)

        if data:
            data_length = len(data)
            bytes_written = 0
            LOGGER.info(f"Data length: {data_length}")

            while bytes_written < data_length:
                if (maxwrite - writesize) < (data_length - bytes_written):
                    count = maxwrite - writesize
                else:
                    count = data_length - bytes_written

                write_blob_size = bytes_written
                LOGGER.debug(f"Writing data from byte {write_blob_size} to {write_blob_size + count}")

                try:
                    self.write_fragment(
                        key,
                        namespace=namespace,
                        data=data[write_blob_size : write_blob_size + count],
                        offset=write_blob_size,
                        count=count,
                    )
                except Exception as e:
                    LOGGER.error(f"Failed to write fragment for blob with key {key} in namespace {namespace}: {e}")
                    raise

                bytes_written += count
                LOGGER.debug(f"{bytes_written} bytes written so far.")

        try:
            result = self.finalize(key, namespace=namespace)
            LOGGER.info(f"Finalization successful for key: {key} in namespace: {namespace}")
            return result
        except Exception as e:
            LOGGER.error(f"Failed to finalize the write for blob with key {key} in namespace {namespace}: {e}")
            raise

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
        LOGGER.info(f"Starting fragmented write for blob with key: {key} in namespace: {namespace}")
        LOGGER.debug(f"Fragment write params: offset={offset}, count={count}")

        lib = self.gethprestchifhandle()
        lib.write_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.write_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        # Call the external library function
        try:
            ptr = lib.write_fragment(offset, count, name, namespace)
        except Exception as e:
            LOGGER.error(f"Error while calling write_fragment for key: {key} in namespace: {namespace}: {e}")
            raise

        LOGGER.debug(f"Received pointer for write_fragment call, preparing data for send.")

        sendpacket = ptr[: lib.size_of_writeRequest()]

        if isinstance(data, str):
            data = data.encode("utf-8")

        dataarr = bytearray(sendpacket)
        dataarr.extend(memoryview(data))

        LOGGER.debug(f"Data to be sent: {dataarr[:50]}... (first 50 bytes)")

        # Send the data
        try:
            resp = self._send_receive_raw(dataarr)
        except Exception as e:
            LOGGER.error(f"Error during sending/receiving raw data for blob with key: {key}: {e}")
            raise

        # Check for errors in response
        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
            LOGGER.error(f"Write fragment failed for key: {key} in namespace: {namespace}. Error code: {errorcode}")
            raise HpIloError(errorcode)

        LOGGER.info(f"Fragmented write successful for key: {key} in namespace: {namespace}")

        self.unloadchifhandle(lib)

        return resp

    def delete(self, key, namespace, retries=0):
        """Delete the blob.

        :param key: The blob key to be deleted.
        :type key: str
        :param namespace: The blob namespace to delete the key from.
        :type namespace: str
        :param retries: The number of retries if deletion fails (default 0).
        :type retries: int
        """
        LOGGER.info(f"Starting blob deletion: key={key}, namespace={namespace}, retries={retries}")

        lib = self.gethprestchifhandle()
        lib.delete_blob.argtypes = [c_char_p, c_char_p]
        lib.delete_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key.encode("utf-8"))
        namspace = create_string_buffer(namespace.encode("utf-8"))

        ptr = lib.delete_blob(name, namspace)
        data = ptr[: lib.size_of_deleteRequest()]
        data = bytearray(data)

        while retries <= self.max_retries:
            LOGGER.debug(f"Attempt {retries + 1} of {self.max_retries}: Sending raw delete request.")

            resp = self._send_receive_raw(data)

            # Checking for errors in the received response
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            LOGGER.debug(f"Received error code: {errorcode}")

            if errorcode == BlobReturnCodes.BADPARAMETER:
                LOGGER.warning(
                    f"BADPARAMETER error received (retries left: {self.max_retries - retries}). Retrying after {self.delay} seconds."
                )
                if retries < self.max_retries:
                    time.sleep(self.delay)
                    retries += 1
                    self.delay += 0.05
                else:
                    LOGGER.warning(f"Max retries reached. Unable to delete blob key={key}. Raising Blob2OverrideError.")
                    raise Blob2OverrideError(errorcode)
            elif errorcode not in (BlobReturnCodes.SUCCESS, BlobReturnCodes.NOTMODIFIED):
                LOGGER.error(f"Error during blob deletion: {errorcode}. Raising HpIloError.")
                raise HpIloError(errorcode)
            else:
                LOGGER.info(f"Blob deletion successful for key={key} in namespace={namespace}.")
                break

        self.unloadchifhandle(lib)

        LOGGER.info(f"Exiting delete function for key={key}. Final error code: {errorcode}")
        return errorcode

    def list(self, namespace):
        """List operation to retrieve all blobs in a given namespace.

        :param namespace: The blob namespace to retrieve the keys from.
        :type namespace: str.
        """
        LOGGER.info(f"Starting blob listing operation for namespace: {namespace}")

        lib = self.gethprestchifhandle()
        lib.list_blob.argtypes = [c_char_p]
        lib.list_blob.restype = POINTER(c_ubyte)

        namespace = create_string_buffer(namespace.encode("utf-8"))

        LOGGER.debug("Sending list blob request to iLO.")
        ptr = lib.list_blob(namespace)
        data = ptr[: lib.size_of_listRequest()]
        data = bytearray(data)

        # Send and receive raw data
        resp = self._send_receive_raw(data)

        # Check for errors in the response
        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        LOGGER.debug(f"Received error code: {errorcode}")

        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
            LOGGER.error(f"Error during blob listing: {errorcode}. Raising HpIloError.")
            raise HpIloError(errorcode)

        # Padding response to match expected size
        resp = resp + b"\0" * (lib.size_of_listResponse() - len(resp))

        # Unload the handler
        self.unloadchifhandle(lib)

        LOGGER.info(f"Blob listing successful for namespace: {namespace}")
        return resp

    def finalize(self, key, namespace):
        """Finalize the blob.

        :param key: The blob key to be finalized.
        :type key: str.
        :param namespace: The blob namespace to finalize the key in.
        :type namespace: str.
        """
        LOGGER.info(f"Starting blob finalize operation for key: {key}, namespace: {namespace}")

        # Getting the handler library
        lib = self.gethprestchifhandle()
        lib.finalize_blob.argtypes = [c_char_p, c_char_p]
        lib.finalize_blob.restype = POINTER(c_ubyte)

        # Preparing request data
        name = create_string_buffer(key.encode("utf-8"))
        namespace = create_string_buffer(namespace.encode("utf-8"))

        # Sending the finalize request
        LOGGER.debug("Sending finalize blob request to iLO.")
        ptr = lib.finalize_blob(name, namespace)
        data = ptr[: lib.size_of_finalizeRequest()]
        data = bytearray(data)

        # Send and receive raw data
        resp = self._send_receive_raw(data)

        # Checking for errors in the response
        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        LOGGER.debug(f"Received error code: {errorcode}")

        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
            LOGGER.error(f"Error during blob finalize: {errorcode}. Raising HpIloError.")
            raise HpIloError(errorcode)

        # Unload the handler
        self.unloadchifhandle(lib)

        LOGGER.info(f"Blob finalize successful for key: {key}, namespace: {namespace}")
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
        # Log generated keys
        rqt_key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        rsp_key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        LOGGER.debug("Generated request key: %s, response key: %s", rqt_key, rsp_key)

        lib = self.gethprestchifhandle()

        # Log request size check
        if len(req_data) < (lib.size_of_restImmediateRequest() + lib.max_write_size()):
            LOGGER.debug("Proceeding with immediate request (no blob required).")

            # Rest immediate operation
            lib.rest_immediate.argtypes = [c_uint, c_char_p, c_char_p]
            lib.rest_immediate.restype = POINTER(c_ubyte)

            name = create_string_buffer(rsp_key.encode("utf-8"))
            namespace = create_string_buffer(rsp_namespace.encode("utf-8"))

            ptr = lib.rest_immediate(len(req_data), name, namespace)
            sendpacket = ptr[: lib.size_of_restImmediateRequest()]
            mode = False
        else:
            # Log that we're handling large data
            LOGGER.debug("Data is large, proceeding with create/write operations.")

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

        LOGGER.debug("Sending request data to iLO.")

        # Sending the data
        resp = self._send_receive_raw(data)

        # Log response processing
        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        LOGGER.debug("Received error code: %s", errorcode)

        if errorcode == BlobReturnCodes.NOTFOUND:
            LOGGER.error("Blob not found for key: %s in namespace: %s", rsp_key, rsp_namespace)
            raise BlobNotFoundError(rsp_key, rsp_namespace)

        recvmode = struct.unpack("<I", bytes(resp[12:16]))[0]

        fixdlen = lib.size_of_restResponseFixed()
        response = resp[fixdlen : struct.unpack("<I", bytes(resp[16:20]))[0] + fixdlen]

        tmpresponse = None
        if errorcode == BlobReturnCodes.SUCCESS and not mode:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
                LOGGER.debug("Successfully received response: %s", tmpresponse)
        elif errorcode == BlobReturnCodes.NOTMODIFIED and not mode:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
                LOGGER.debug("No modification detected, response: %s", tmpresponse)
        elif errorcode == BlobReturnCodes.SUCCESS:
            if recvmode == 0:
                tmpresponse = "".join(map(chr, response))
                LOGGER.debug("Successfully received response after modification: %s", tmpresponse)
        elif recvmode == 0:
            LOGGER.error("Error processing response: %s", errorcode)
            raise HpIloError(errorcode)

        # Cleanup and response handling
        self.unloadchifhandle(lib)

        if not tmpresponse and recvmode == 1:
            tmpresponse = self.read(rsp_key, rsp_namespace)
            LOGGER.debug("Fallback response: %s", tmpresponse)

            try:
                self.delete(rsp_key, rsp_namespace)
                LOGGER.debug("Successfully deleted blob with key: %s", rsp_key)
            except Exception as excp:
                LOGGER.warning("Error deleting blob: %s", excp)
                raise excp
        else:
            try:
                self.delete(rsp_key, rsp_namespace)
                LOGGER.debug("Successfully deleted blob with key: %s", rsp_key)
            except Blob2OverrideError:
                LOGGER.warning("Blob delete skipped due to Blob2OverrideError.")
            except HpIloChifPacketExchangeError:
                LOGGER.warning("Packet exchange error during delete operation.")
            except Exception as excp:
                LOGGER.warning("Error deleting blob: %s", excp)
                raise excp

        return tmpresponse

    def get_security_state(self):
        """Get information for the current security state"""
        LOGGER.debug("Fetching security state from iLO.")

        lib = self.gethprestchifhandle()
        lib.get_security_state.argtypes = []
        lib.get_security_state.restype = POINTER(c_ubyte)

        try:
            # Fetch the security state
            ptr = lib.get_security_state()
            data = ptr[: lib.size_of_securityStateRequest()]
            data = bytearray(data)
            LOGGER.debug("Received raw security state data of size: %d", len(data))

            # Send and receive raw data
            resp = self._send_receive_raw(data)
            LOGGER.debug("Raw response received: %s", resp)

            # Extract the error code from the response
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            LOGGER.debug("Received error code: %d", errorcode)

            # Check for errors and raise exceptions if needed
            if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
                LOGGER.error("Error occurred with code: %d", errorcode)
                raise HpIloError(errorcode)

            # Attempt to retrieve the security state from the response
            try:
                securitystate = struct.unpack("<c", bytes(resp[72]))[0]
                LOGGER.debug("Security state extracted as character: %s", securitystate)
            except Exception as e:
                # Fallback for non-character extraction (may be an integer)
                securitystate = int(resp[72])
                LOGGER.debug("Failed to extract character. Security state interpreted as integer: %d", securitystate)

            self.unloadchifhandle(lib)

            LOGGER.debug("Returning security state: %s", securitystate)
            return securitystate

        except Exception as e:
            LOGGER.error("Error while fetching security state: %s", str(e))
            raise

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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
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
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def _send_receive_raw(self, indata):
        """Send and receive raw function for blob operations

        :param indata: The data to be sent to blob operation.
        :type indata: str.

        """
        LOGGER.info("Starting _send_receive_raw operation.")
        excp = None

        for attempt in range(1, 4):  # 3 attempts
            try:
                LOGGER.debug("Attempt %d: Sending data to iLO.", attempt)
                resp = self.channel.send_receive_raw(indata, 10)
                LOGGER.info("Data successfully sent and received on attempt %d.", attempt)
                return resp
            except Exception as exp:
                LOGGER.warning("Attempt %d failed. Error: %s", attempt, str(exp))
                self.channel.close()
                LOGGER.info("Reinitializing communication channel with iLO.")
                lib = self.gethprestchifhandle()
                self.channel = HpIlo(dll=lib)
                excp = exp  # Store last exception for final raise

        LOGGER.error("All attempts to send/receive raw data have failed.")
        if excp:
            raise excp  # Raise only after all retries fail

    def cert_login(self, cert_file, priv_key, key_pass):
        lib = self.gethprestchifhandle()
        lib.login_cert.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        lib.login_cert.restype = c_char_p

        token = lib.login_cert(self.channel.fhandle, cert_file, priv_key, key_pass)
        return token

    @staticmethod
    def gethprestchifhandle():
        """Multi platform handle for chif hprest library"""
        LOGGER.debug("Retrieving Chif library handle.")
        excp = None
        libhandle = None
        if os.name != "nt":
            libpath = "/opt/ilorest/lib64/libilorestchif.so"
            if os.path.isfile(libpath):
                libhandle = cdll.LoadLibrary(libpath)
        if not libhandle:
            libnames = (
                ["ilorest_chif.dll"]
                if os.name == "nt"
                else [
                    "ilorest_chif_dev.so",
                    "ilorest_chif.so",
                ]
            )
            for libname in libnames:
                try:
                    libpath = BlobStore2.checkincurrdirectory(libname)
                    # LOGGER.debug("Loading Library %s for libhpsrv", libpath)
                    libhandle = cdll.LoadLibrary(libpath)
                    if libhandle:
                        # LOGGER.debug("Got Libhandle %s for libhpsrv", libhandle)
                        break
                except Exception as exp:
                    excp = exp

        if libhandle:
            LOGGER.debug("Successfully loaded Chif library.")
            BlobStore2.setglobalhprestchifrandnumber(libhandle)
            return libhandle
        else:
            import site

            site_packages = site.getsitepackages()
            for package in site_packages:
                try:
                    if os.name != "nt":
                        libpath = os.path.join(package, "ilorest", "chiflibrary", "ilorest_chif.so")
                    else:
                        libpath = os.path.join(package, "ilorest", "chiflibrary", "ilorest_chif.dll")
                    libhandle = cdll.LoadLibrary(libpath)
                except Exception as exp:
                    excp = exp
                if libhandle:
                    LOGGER.debug("Successfully loaded Chif library.")
                    BlobStore2.setglobalhprestchifrandnumber(libhandle)
                    return libhandle
        LOGGER.error("Failed to load Chif library: %s", str(e))
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
    def initializecreds(username=None, password=None, log_dir=None):
        """
        Initialize Chif and handle high-security credentials.

        :param username: The username to login.
        :type username: str
        :param password: The password to login.
        :type password: str
        :param log_dir: The directory where logs will be stored.
        :type log_dir: str
        :return: True if successful, False otherwise.
        :rtype: bool
        :raises Blob2SecurityError: If security check fails.
        :raises HpIloInitialError: If credential verification fails.
        """

        LOGGER.info("Initializing Chif credentials with security settings.")
        LOGGER.debug("Username provided: %s, Log directory: %s", username, log_dir)

        try:
            dll = BlobStore2.gethprestchifhandle()

            # Enable debug output if LOGGER level is DEBUG
            if LOGGER.isEnabledFor(logging.DEBUG) and log_dir:
                logdir_c = create_string_buffer(log_dir.encode("utf-8"))
                LOGGER.debug("Enabling debug output to directory: %s", log_dir)
                dll.enabledebugoutput(logdir_c)

            # Initialize Chif
            LOGGER.debug("Calling ChifInitialize()")
            dll.ChifInitialize(None)

            # If username is provided, proceed with security authentication
            if username:
                if not password:
                    LOGGER.warning("Password is missing while username is provided.")
                    return False  # Invalid credentials

                if dll.ChifIsSecurityRequired() > 0:
                    LOGGER.info("High security mode detected. Authenticating credentials.")

                    dll.initiate_credentials.argtypes = [c_char_p, c_char_p]
                    dll.initiate_credentials.restype = POINTER(c_ubyte)

                    usernew = create_string_buffer(username.encode("utf-8"))
                    passnew = create_string_buffer(password.encode("utf-8"))

                    LOGGER.debug("Initiating credential verification.")
                    dll.initiate_credentials(usernew, passnew)

                    credreturn = dll.ChifVerifyCredentials()
                    if credreturn == BlobReturnCodes.SUCCESS:
                        LOGGER.info("Credentials verified successfully.")
                    elif credreturn == hpiloreturncodes.CHIFERR_AccessDenied:
                        LOGGER.error("Access Denied: Invalid credentials.")
                        raise Blob2SecurityError()
                    else:
                        LOGGER.error("Error %s occurred while trying to open a channel to iLO.", credreturn)
                        raise HpIloInitialError(f"Error {credreturn} occurred while trying to open a channel to iLO.")
                else:
                    LOGGER.info("Security not required. Disabling security.")
                    dll.ChifDisableSecurity()
            else:
                LOGGER.debug("No username provided. Checking security requirement.")
                if dll.ChifIsSecurityRequired() > 0:
                    LOGGER.warning("High security mode detected but no credentials provided.")
                    return False
                else:
                    LOGGER.info("Security not required. Disabling security.")
                    dll.ChifDisableSecurity()

            return True

        except Exception as e:
            LOGGER.exception("Exception occurred during Chif initialization: %s", str(e))
            raise

        finally:
            LOGGER.debug("Unloading Chif handle.")
            BlobStore2.unloadchifhandle(dll)

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
            libpath = [os.path.join(pat, libname) for pat in paths if os.path.isfile(os.path.join(pat, libname))]
            libpath = libpath[0] if libpath else libname

        return libpath

    @staticmethod
    def unloadchifhandle(lib):
        """
        Release a handle on the Chif iLOrest library.

        :param lib: The library handle provided by loading the Chif library.
        :type lib: library handle
        """
        if lib is None:
            LOGGER.warning("unloadchifhandle called with None library handle. Nothing to release.")
            return

        try:
            libhandle = lib._handle
            LOGGER.info("Releasing Chif library handle: %s", libhandle)

            if os.name == "nt":
                LOGGER.debug("Using Windows FreeLibrary to release handle.")
                windll.kernel32.FreeLibrary(None, handle=libhandle)
            else:
                LOGGER.debug("Using dlclose to release handle on Linux/Unix.")
                dlclose(libhandle)

            LOGGER.info("Successfully released Chif library handle.")

        except Exception as e:
            LOGGER.exception("Error while unloading Chif library handle: %s", str(e))
