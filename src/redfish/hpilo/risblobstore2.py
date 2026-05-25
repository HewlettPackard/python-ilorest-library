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
import platform
import sysconfig
import logging
import random
import struct
import string
import time
import ctypes
from ctypes import POINTER, c_char_p, c_ubyte, c_uint, c_ushort, c_void_p, create_string_buffer

from redfish.hpilo.rishpilo import BlobReturnCodes as hpiloreturncodes
from redfish.hpilo.rishpilo import (
    HpIlo,
    HpIloChifPacketExchangeError,
    HpIloInitialError,
)
from redfish.log_utils import RestDebugLogRotator

if os.name == "nt":
    from ctypes import windll
else:
    from _ctypes import dlclose

# Flags from <dlfcn.h> (Linux/Unix)
RTLD_LAZY = 0x00001
RTLD_GLOBAL = 0x00100

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

    def __init__(self, log_dir=None, username=None, password=None):
        lib = self.gethprestchifhandle()
        self.log_dir = log_dir

        self.channel = None  # guard __del__ in case HpIlo() raises below
        self.channel = HpIlo(dll=lib, log_dir=log_dir)

        # Set credentials after channel creation so HpIlo's internal ChifInitialize
        # doesn't wipe them out. Ping usually passes without creds.
        if username and password:
            lib.initiate_credentials.argtypes = [c_char_p, c_char_p]
            lib.initiate_credentials.restype = POINTER(c_ubyte)
            usernew = create_string_buffer(username.encode("utf-8"))
            passnew = create_string_buffer(password.encode("utf-8"))
            lib.initiate_credentials(usernew, passnew)
            LOGGER.debug("Credentials set after BlobStore2 channel creation")

        self.unloadchifhandle(lib)

        # Retry calibration for sustained 0.5 Hz login (watch -n 2).
        #
        # With resource leaks fixed (cert_login and _send_receive_raw now
        # release CHIF handles), concurrent sessions stay at ~3-5 instead
        # of accumulating unboundedly.  This means iLO's 16 CHIF slots are
        # no longer starved, and BADPARAMETER bursts are shorter.
        #
        self.max_retries = 15
        self.max_read_retries = 10
        self.delay = 0.25
        self.delay_step = 0.10
        self.max_jitter = 1.5
        self.max_delay = 1.5
        self.read_retry_delay = 0.10

        LOGGER.debug("BlobStore initialized with log directory: %s", log_dir)

    def __del__(self):
        """Blob store 2 close channel function"""
        if hasattr(self, "channel"):
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
        LOGGER.debug("Attempting to create blob: Key=%s, Namespace=%s", key, namespace)

        lib = None
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

            LOGGER.debug("Sending blob creation request")
            resp = self._send_receive_raw(data)

            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
                LOGGER.error("Blob creation failed. Error Code: %d", errorcode)
                raise HpIloError(errorcode)

            LOGGER.debug("Blob creation successful for Key=%s, Namespace=%s", key, namespace)
            return resp


        finally:
            LOGGER.debug("Unloading library handle")
            if lib is not None:
                self.unloadchifhandle(lib)

    def get_info(self, key, namespace, retries=0):
        """Get information for a particular blob.

        :param key: The blob key to retrieve.
        :type key: str.
        :param namespace: The blob namespace to retrieve the key from.
        :type namespace: str.

        """
        LOGGER.debug(f"get_info called with key='{key}', namespace='{namespace}', retries={retries}")

        lib = self.gethprestchifhandle()
        lib.get_info.argtypes = [c_char_p, c_char_p]
        lib.get_info.restype = POINTER(c_ubyte)

        delay = self.delay
        resp = None
        try:
            while retries <= self.max_retries:
                LOGGER.debug(f"Attempt {retries+1}/{self.max_retries} - Sending request to iLO.")

                # Build a fresh request packet on every attempt so that
                # channel reinitialisation inside _send_receive_raw does
                # not leave us with a stale packet from the old session.
                name = create_string_buffer(key.encode("utf-8"))
                namspace = create_string_buffer(namespace.encode("utf-8"))
                ptr = lib.get_info(name, namspace)
                data = bytearray(ptr[: lib.size_of_infoRequest()])

                resp = self._send_receive_raw(data)
                errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
                header = resp[:8].hex()

                LOGGER.debug(f"Response received - Error Code: {errorcode}, Headers: {header}, Size: {len(resp)} bytes")

                if errorcode == BlobReturnCodes.BADPARAMETER:
                    if retries < self.max_retries:
                        jitter = random.uniform(0, self.max_jitter)
                        sleep_duration = delay + jitter
                        LOGGER.warning(
                            f"BADPARAMETER error received. Retrying in {sleep_duration:.4f} seconds "
                            f"(base={delay:.4f}, jitter={jitter:.4f})... "
                            f"({retries+1}/{self.max_retries})"
                        )
                        time.sleep(sleep_duration)
                        retries += 1
                        delay += self.delay_step
                        delay = min(delay, self.max_delay)
                        continue
                    else:
                        # Recoverable error
                        LOGGER.warning(f"Max retries ({self.max_retries}) exceeded. Raising Blob2OverrideError.")
                        raise Blob2OverrideError(errorcode)

                elif errorcode == BlobReturnCodes.NOTFOUND:
                    LOGGER.error(f"BlobNotFoundError: key='{key}', namespace='{namespace}'")
                    raise BlobNotFoundError(key, namespace)

                elif errorcode not in (BlobReturnCodes.SUCCESS, BlobReturnCodes.NOTMODIFIED):
                    LOGGER.error(f"HpIloError: Unexpected error code {errorcode}.")
                    raise HpIloError(errorcode)

                else:
                    LOGGER.debug("Request successful. Extracting response data.")
                    break

            response = resp[lib.size_of_responseHeaderBlob() :]
        finally:
            self.unloadchifhandle(lib)

        LOGGER.debug(f"get_info completed successfully for key='{key}', namespace='{namespace}'.")
        return response

    def read(self, key, namespace, retries=0):
        """Read a particular blob

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.

        """
        LOGGER.debug("Starting blob read: Key=%s, Namespace=%s, Retry=%d", key, namespace, retries)

        try:
            lib = self.gethprestchifhandle()
            maxread = lib.max_read_size()
            readsize = lib.size_of_readRequest()
            readhead = lib.size_of_responseHeaderBlob()
            LOGGER.debug(f"Read parameters: maxread={maxread}, readsize={readsize}, readhead={readhead}")
            self.unloadchifhandle(lib)

            # Get blob metadata
            LOGGER.debug("Fetching blob info to determine size.")
            blob_info = self.get_info(key, namespace)
            blobsize = struct.unpack("<I", bytes(blob_info[0:4]))[0]
            LOGGER.debug("Blob size determined: %d bytes", blobsize)

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
                    LOGGER.debug(f"Zero bytes read in fragment. Fragment metadata: offset={bytes_read}, count={count}")
                    if retries < self.max_read_retries:
                        LOGGER.debug(
                            "Read attempt failed. Retrying (Attempt %d/%d).", retries + 1, self.max_read_retries
                        )
                        time.sleep(self.read_retry_delay)
                        return self.read(key=key, namespace=namespace, retries=retries + 1)
                    else:
                        LOGGER.debug("Maximum read retries (%d) exceeded.", self.max_read_retries)
                        raise BlobRetriesExhaustedError()

                data.extend(recvpkt[newreadsize : newreadsize + bytesread])
                bytes_read += bytesread
                LOGGER.debug("Total bytes read so far: %d/%d", bytes_read, blobsize)

            LOGGER.debug("Blob read successfully: Key=%s, Namespace=%s, Total Bytes=%d", key, namespace, len(data))
            return data

        except BlobRetriesExhaustedError:
            raise
        except Blob2OverrideError:
            raise
        except BlobNotFoundError:
            raise
        except HpIloError:
            raise
        except Exception as e:
            LOGGER.warning("Unexpected error during blob read: %s", str(e))
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
        LOGGER.debug(
            "Starting fragmented blob read: Key=%s, Namespace=%s, Offset=%d, Count=%d", key, namespace, offset, count
        )

        lib = None
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

            LOGGER.debug("Sending fragmented read request to iLO.")
            resp = self._send_receive_raw(data)

            # Check response error code
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            LOGGER.debug(
                f"Response received - Headers: Status={errorcode}, Size={len(resp)}, Expected Size={response_size}"
            )
            if len(resp) < response_size:
                LOGGER.warning("Received response smaller than expected. Padding response.")
                resp = resp + b"\0" * (response_size - len(resp))

            LOGGER.debug("Fragmented blob read successful: Key=%s, Bytes Received=%d", key, len(resp))
            return resp

        finally:
            if lib is not None:
                self.unloadchifhandle(lib)

    def write(self, key, namespace, data=None):
        """Write a particular blob

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written.
        :type data: str.

        """
        LOGGER.debug(f"Starting to write blob with key: {key} in namespace: {namespace}")

        lib = self.gethprestchifhandle()
        maxwrite = lib.max_write_size()
        writesize = lib.size_of_writeRequest()

        LOGGER.debug(f"Max write size: {maxwrite}, Write request size: {writesize}")

        self.unloadchifhandle(lib)

        if data:
            data_length = len(data)
            bytes_written = 0
            LOGGER.debug(f"Data length: {data_length}")

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
            LOGGER.debug(f"Finalization successful for key: {key} in namespace: {namespace}")
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
        LOGGER.debug(f"Starting fragmented write for blob with key: {key} in namespace: {namespace}")
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


        sendpacket = ptr[: lib.size_of_writeRequest()]

        if isinstance(data, str):
            data = data.encode("utf-8")

        dataarr = bytearray(sendpacket)
        dataarr.extend(memoryview(data))

        # Send the data
        try:
            resp = self._send_receive_raw(dataarr)
        except Exception as e:
            LOGGER.error(f"Error during sending/receiving raw data for blob with key: {key}: {e}")
            self.unloadchifhandle(lib)
            raise

        # Check for errors in response
        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
            LOGGER.error(f"Write fragment failed for key: {key} in namespace: {namespace}. Error code: {errorcode}")
            self.unloadchifhandle(lib)
            raise HpIloError(errorcode)

        LOGGER.debug(f"Fragmented write successful for key: {key} in namespace: {namespace}")

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
        LOGGER.debug(f"Starting blob deletion: key={key}, namespace={namespace}, retries={retries}")

        lib = self.gethprestchifhandle()
        lib.delete_blob.argtypes = [c_char_p, c_char_p]
        lib.delete_blob.restype = POINTER(c_ubyte)

        delay = self.delay
        errorcode = None
        try:
            while retries <= self.max_retries:
                LOGGER.debug(f"Attempt {retries + 1} of {self.max_retries}: Sending raw delete request.")

                # Build a fresh request packet on every attempt so that
                # channel reinitialisation inside _send_receive_raw does
                # not leave us with a stale packet from the old session.
                name = create_string_buffer(key.encode("utf-8"))
                namspace = create_string_buffer(namespace.encode("utf-8"))
                ptr = lib.delete_blob(name, namspace)
                data = bytearray(ptr[: lib.size_of_deleteRequest()])

                resp = self._send_receive_raw(data)

                # Checking for errors in the received response
                errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
                LOGGER.debug(f"Received error code: {errorcode}")

                if errorcode == BlobReturnCodes.BADPARAMETER:
                    if retries < self.max_retries:
                        jitter = random.uniform(0, self.max_jitter)
                        sleep_duration = delay + jitter
                        LOGGER.warning(
                            f"Retrying after {sleep_duration:.4f} seconds "
                            f"(base={delay:.4f}, jitter={jitter:.4f})."
                        )
                        time.sleep(sleep_duration)
                        retries += 1
                        delay += self.delay_step
                        delay = min(delay, self.max_delay)
                        continue
                    else:
                        # Recoverable error
                        LOGGER.warning(f"Max retries reached. Unable to delete blob key={key}. Raising Blob2OverrideError.")
                        raise Blob2OverrideError(errorcode)
                elif errorcode not in (BlobReturnCodes.SUCCESS, BlobReturnCodes.NOTMODIFIED):
                    raise HpIloError(errorcode)
                else:
                    break
        finally:
            self.unloadchifhandle(lib)

        return errorcode

    def list(self, namespace):
        """List operation to retrieve all blobs in a given namespace.

        :param namespace: The blob namespace to retrieve the keys from.
        :type namespace: str.
        """
        LOGGER.debug(f"Starting blob listing operation for namespace: {namespace}")

        lib = self.gethprestchifhandle()
        lib.list_blob.argtypes = [c_char_p]
        lib.list_blob.restype = POINTER(c_ubyte)

        namespace = create_string_buffer(namespace.encode("utf-8"))

        LOGGER.debug("Sending list blob request to iLO.")
        ptr = lib.list_blob(namespace)
        data = ptr[: lib.size_of_listRequest()]
        data = bytearray(data)

        try:
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
        finally:
            self.unloadchifhandle(lib)

        LOGGER.debug(f"Blob listing successful for namespace: {namespace}")
        return resp

    def finalize(self, key, namespace):
        """Finalize the blob.

        :param key: The blob key to be finalized.
        :type key: str.
        :param namespace: The blob namespace to finalize the key in.
        :type namespace: str.
        """
        LOGGER.debug(f"Starting blob finalize operation for key: {key}, namespace: {namespace}")

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

        try:
            # Send and receive raw data
            resp = self._send_receive_raw(data)

            # Checking for errors in the response
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
            LOGGER.debug(f"Received error code: {errorcode}")

            if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
                LOGGER.error(f"Error during blob finalize: {errorcode}. Raising HpIloError.")
                raise HpIloError(errorcode)
        finally:
            self.unloadchifhandle(lib)

        LOGGER.debug(f"Blob finalize successful for key: {key}, namespace: {namespace}")
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
        LOGGER.debug(f"Generated request key: {rqt_key}, response key: {rsp_key}")
        LOGGER.debug(f"Request data size: {len(req_data)} bytes")

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
            except Exception:
                raise
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
                raise

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

            # Send and receive raw data
            resp = self._send_receive_raw(data)

            # Extract the error code from the response
            errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]

            # Check for errors and raise exceptions if needed
            if not (errorcode == BlobReturnCodes.SUCCESS or errorcode == BlobReturnCodes.NOTMODIFIED):
                LOGGER.error("Error occurred with code: %d", errorcode)
                raise HpIloError(errorcode)

            # Attempt to retrieve the security state from the response
            try:
                securitystate = struct.unpack("<c", bytes(resp[72]))[0]
                LOGGER.debug("Security state extracted as character: %s", securitystate)
            except Exception:
                # Fallback for non-character extraction (may be an integer)
                securitystate = int(resp[72])
                LOGGER.debug("Failed to extract character. Security state interpreted as integer: %d", securitystate)

            LOGGER.debug("Returning security state: %s", securitystate)
            return securitystate

        finally:
            self.unloadchifhandle(lib)

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
        excp = None

        for attempt in range(1, 4):  # 3 attempts
            try:
                resp = self.channel.send_receive_raw(indata, 10)
                # Log response details
                errorcode = None
                if len(resp) >= 12:
                    errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
                    LOGGER.debug(
                        f"Response details - Size: {len(resp)} bytes, Error Code: {errorcode}, "
                        f"Headers: {resp[:8].hex()}"
                    )
                return resp
            except Exception as exp:
                self.channel.close()
                LOGGER.warning(
                    "Attempt %d/3 failed (%s). Reinitializing CHIF channel.",
                    attempt, exp,
                )
                lib = self.gethprestchifhandle()
                self.channel = HpIlo(dll=lib, log_dir=self.log_dir)
                self.unloadchifhandle(lib)
                excp = exp

        if excp:
            raise excp

    def cert_login(self, cert_file, priv_key, key_pass):
        lib = self.gethprestchifhandle()
        try:
            lib.login_cert.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
            lib.login_cert.restype = c_char_p

            token = lib.login_cert(self.channel.fhandle, cert_file, priv_key, key_pass)
            return token
        finally:
            self.unloadchifhandle(lib)

    @staticmethod
    def gethprestchifhandle():
        """Multi-platform handle for Chif hprest library"""

        if platform.system() == "Darwin":
            raise ChifDllMissingError()

        LOGGER.debug("Retrieving Chif library handle.")
        excp = None
        libhandle = None
        arch = platform.machine().lower()
        is_windows = os.name == "nt"

        def load_with_flags(path):
            """Load library using RTLD_LAZY | RTLD_GLOBAL to match dlopen behavior."""
            return ctypes.CDLL(path, mode=RTLD_LAZY | RTLD_GLOBAL)

        # 1. Try fixed path on Linux
        if not is_windows:
            libpath = "/opt/ilorest/lib64/libilorestchif.so"
            if os.path.isfile(libpath):
                try:
                    libhandle = load_with_flags(libpath)
                except Exception as exp:
                    excp = exp

        # 2. Try current directory for known filenames
        if not libhandle:
            libnames = ["ilorest_chif.dll"] if is_windows else ["ilorest_chif_dev.so", "ilorest_chif.so"]
            for libname in libnames:
                try:
                    libpath = BlobStore2.checkincurrdirectory(libname)
                    libhandle = load_with_flags(libpath)
                    if libhandle:
                        break
                except Exception as exp:
                    excp = exp

        # 3. Try locating from installed site-packages
        if not libhandle:
            try:
                site_packages = [sysconfig.get_paths()["purelib"]]
            except Exception as exp:
                LOGGER.debug("Failed to get site-packages path: %s", str(exp))
                site_packages = []

            for package in site_packages:
                try:
                    # Base chif library path
                    chif_dir = os.path.join(package, "ilorest", "chiflibrary")

                    if is_windows:
                        chif_lib_name = "ilorest_chif.dll"
                        libpath = os.path.join(chif_dir, chif_lib_name)
                    else:
                        chif_lib_name = "ilorest_chif.so"
                        libpath = os.path.join(chif_dir, chif_lib_name)

                        # Try arch-specific subfolder as fallback
                        if arch in ("aarch64", "arm64"):
                            libpath = os.path.join(chif_dir, "arm", chif_lib_name)

                    if os.path.isfile(libpath):
                        libhandle = load_with_flags(libpath)
                        if libhandle:
                            break
                except Exception as exp:
                    excp = exp

        # Final result
        if libhandle:
            LOGGER.debug("Successfully loaded Chif library.")
            BlobStore2.setglobalhprestchifrandnumber(libhandle)
            return libhandle
        else:
            LOGGER.debug("Failed to load Chif library: %s", str(excp))
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

        SECURITY NOTE: This method does NOT cache credentials to avoid security risks.
        Credentials are only used for initialization and verification, then discarded.

        For applications that need to maintain state (e.g., long-running services),
        credentials should be passed explicitly to each BlobStore2 constructor call.

        For CLI tools that launch fresh each time (e.g., ilorest), credential caching
        would provide no benefit since the process memory is cleared on exit anyway.

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

        LOGGER.debug("Initializing Chif credentials with security settings.")
        LOGGER.debug("Username provided: %s, Log directory: %s", username, log_dir)

        dll = None
        try:
            dll = BlobStore2.gethprestchifhandle()

            # Enable debug output if LOGGER level is DEBUG
            if LOGGER.isEnabledFor(logging.DEBUG) and log_dir:
                # Rotate rest.debug.log if it exceeds size threshold
                RestDebugLogRotator.rotate_rest_debug_log(log_dir, max_size_mb=2, max_backups=3)

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

                # Check security level requirement
                LOGGER.debug("Checking iLO security requirements")
                security_level = dll.ChifIsSecurityRequired()
                LOGGER.debug(f"Security level check returned: {security_level}")
                if security_level > 0:
                    LOGGER.info("High security mode detected. Authenticating credentials.")
                    LOGGER.debug(f"Security requirements: Username={username}, High Security Mode=True")

                    dll.initiate_credentials.argtypes = [c_char_p, c_char_p]
                    dll.initiate_credentials.restype = POINTER(c_ubyte)

                    usernew = create_string_buffer(username.encode("utf-8"))
                    passnew = create_string_buffer(password.encode("utf-8"))

                    LOGGER.debug("Initiating credential verification.")
                    dll.initiate_credentials(usernew, passnew)

                    credreturn = dll.ChifVerifyCredentials()
                    if credreturn == BlobReturnCodes.SUCCESS:
                        LOGGER.info("Credentials verified successfully.")
                        # Note: Credentials are NOT cached for security reasons.
                        # Applications should pass credentials explicitly to BlobStore2 constructor.
                    elif credreturn == hpiloreturncodes.CHIFERR_AccessDenied:
                        LOGGER.error("Access Denied: Invalid credentials.")
                        raise Blob2SecurityError()
                    else:
                        LOGGER.error("Error %s occurred while trying to open a channel to iLO.", credreturn)
                        raise HpIloInitialError(f"Error {credreturn} occurred while trying to open a channel to iLO.")
                else:
                    LOGGER.debug("Security not required. Disabling security.")
                    dll.ChifDisableSecurity()
            else:
                LOGGER.debug("No username provided. Checking security requirement.")
                if dll.ChifIsSecurityRequired() > 0:
                    LOGGER.debug("High security mode detected but no credentials provided.")
                    return False
                else:
                    LOGGER.debug("Security not required. Disabling security.")
                    dll.ChifDisableSecurity()

            return True


        finally:
            LOGGER.debug("Unloading Chif handle.")
            if dll is not None:
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
            LOGGER.debug("unloadchifhandle called with None library handle. Nothing to release.")
            return

        try:
            libhandle = lib._handle
            LOGGER.debug("Releasing Chif library handle: %s", libhandle)

            if os.name == "nt":
                windll.kernel32.FreeLibrary(None, handle=libhandle)
            else:
                dlclose(libhandle)


        except Exception:
            pass
