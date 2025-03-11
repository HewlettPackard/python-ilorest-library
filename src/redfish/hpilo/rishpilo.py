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
"""Base implementation for interaction with the iLO interface"""

# ---------Imports---------

import logging
import os
import struct
import time
from ctypes import byref, c_uint32, c_char_p, c_void_p, create_string_buffer

# ---------End of imports---------
# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)


# ---------End of debug logger---------


class BlobReturnCodes(object):
    """Blob store return codes.

    SUCCESS           success

    """

    SUCCESS = 0
    if os.name != "nt":
        CHIFERR_NoDriver = 19
        CHIFERR_AccessDenied = 13
    else:
        CHIFERR_NoDriver = 2
        CHIFERR_AccessDenied = 5


class HpIloInitialError(Exception):
    """Raised when error during initialization of iLO Chif channel"""

    pass


class HpIloNoChifDriverError(Exception):
    """Raised when error during initialization of iLO Chif channel"""

    pass


class HpIloChifAccessDeniedError(Exception):
    """Raised when error during initialization of iLO Chif channel"""

    pass


class HpIloPrepareAndCreateChannelError(Exception):
    """Raised when error during initialization of iLO Chif channel"""

    pass


class HpIloChifPacketExchangeError(Exception):
    """Raised when errors encountered when exchanging chif packet"""

    pass


class HpIloReadError(Exception):
    """Raised when errors encountered when reading from iLO"""

    pass


class HpIloWriteError(Exception):
    """Raised when errors encountered when writing to iLO"""

    pass


class HpIloSendReceiveError(Exception):
    """Raised when errors encountered when reading form iLO after sending"""

    pass


class HpIloNoDriverError(Exception):
    """Raised when errors encountered when there is no ilo driver"""

    pass


class HpIlo(object):
    """Base class of interaction with iLO"""

    def __init__(self, dll=None, log_dir=None):
        fhandle = c_void_p()
        self.dll = dll
        self.log_dir = log_dir

        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("Initializing with DLL: %s and log directory: %s", dll, log_dir)
            self.dll.enabledebugoutput.argtypes = [c_char_p]
            if log_dir is not None:
                logdir_c = create_string_buffer(log_dir.encode("UTF-8"))
                LOGGER.debug("Enabling debug output with log directory: %s", log_dir)
                self.dll.enabledebugoutput(logdir_c)

        try:
            LOGGER.debug("Calling ChifInitialize...")
            self.dll.ChifInitialize(None)

            self.dll.ChifCreate.argtypes = [c_void_p]
            self.dll.ChifCreate.restype = c_uint32

            LOGGER.debug("Calling ChifCreate...")
            status = self.dll.ChifCreate(byref(fhandle))
            if status != BlobReturnCodes.SUCCESS:
                LOGGER.error("Error occurred while creating channel. Error code: %s", status)
                raise HpIloInitialError(f"Error {status} occurred while trying to create a channel.")

            self.fhandle = fhandle
            LOGGER.debug("Channel created successfully with handle: %s", fhandle)

            if "skip_ping" not in os.environ:
                LOGGER.debug("Attempting to ping iLO...")
                status = self.dll.ChifPing(self.fhandle)
                if status != BlobReturnCodes.SUCCESS:
                    errmsg = f"Error {status} occurred while trying to open a channel to iLO"
                    if status == BlobReturnCodes.CHIFERR_NoDriver:
                        errmsg = "chif"
                    elif status == BlobReturnCodes.CHIFERR_AccessDenied:
                        errmsg = "You must be root/Administrator to use this program."
                    LOGGER.error("Ping failed: %s", errmsg)
                    raise HpIloInitialError(errmsg)

                LOGGER.debug("Ping to iLO successful.")

                # Setting receive timeout
                LOGGER.debug("Setting receive timeout to 60000ms...")
                self.dll.ChifSetRecvTimeout(self.fhandle, 60000)
                LOGGER.debug("Receive timeout set successfully.")
        except Exception as e:
            LOGGER.error("An error occurred during initialization: %s", str(e))
            raise

    def chif_packet_exchange(self, data):
        """Function for handling chif packet exchange

        :param data: data to be sent for packet exchange
        :type data: str

        """
        LOGGER.info("Starting chif packet exchange...")

        # Log the data being sent (truncated if necessary for large data)
        LOGGER.debug(f"Data to be sent: {data[:50]}... (first 50 bytes)")

        datarecv = self.dll.get_max_buffer_size()
        buff = create_string_buffer(bytes(data))
        recbuff = create_string_buffer(datarecv)

        try:
            error = self.dll.ChifPacketExchange(self.fhandle, byref(buff), byref(recbuff), datarecv)
        except Exception as e:
            LOGGER.error(f"Error occurred while calling ChifPacketExchange: {e}")
            raise

        if error != BlobReturnCodes.SUCCESS:
            if error == 8:
                raise HpIloChifPacketExchangeError(
                    "High security mode or Host Authentication has been enabled, Please provide valid credentials \n "
                )
            else:
                raise HpIloChifPacketExchangeError(f"Error {error} occurred while exchanging chif packet")

        LOGGER.info("Chif packet exchange successful.")

        # Process received packet
        pkt = bytearray()

        if datarecv is None:
            LOGGER.warning("Received buffer is empty or None.")
            pkt = bytearray(recbuff[:])
        else:
            pkt = bytearray(recbuff[:datarecv])
            LOGGER.debug(f"Received data: {pkt[:50]}... (first 50 bytes)")

        return pkt

    def send_receive_raw(self, data, retries=10):
        """Function implementing proper send receive retry protocol

        :param data: data to be sent for packet exchange
        :type data: str
        :param retries: number of retries for reading data from iLO
        :type retries: int

        """
        tries = 0
        sequence = struct.unpack("<H", bytes(data[2:4]))[0]

        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("Sending data: %s, retries: %d, initial sequence: %d", data, retries, sequence)

        while tries < retries:
            try:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug("Attempt %d, sending data to iLO", tries + 1)

                resp = self.chif_packet_exchange(data)

                # Log the response data for debugging (consider limiting if large)
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug("Received response: %s", resp)

                # Check for matching sequence
                received_sequence = struct.unpack("<H", bytes(resp[2:4]))[0]
                if sequence != received_sequence:
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug(
                            "Attempt %d: Bad sequence number. Expected: %d, Got: %d",
                            tries + 1,
                            sequence,
                            received_sequence,
                        )
                    continue  # Retry with a new attempt

                # Successfully received response with correct sequence
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug("Attempt %d: Successful response with correct sequence.", tries + 1)

                return resp

            except Exception as excp:
                time.sleep(1)

                # Log exception on each retry attempt
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug("Attempt %d: Error while reading iLO: %s", tries + 1, str(excp))

                if tries == (retries - 1):
                    self.close()

                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug("Final attempt failed. Closing connection.")
                    raise excp  # Raise after final attempt

            tries += 1

        # If retries exhausted, log and raise custom exception
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("Retries exhausted. iLO not responding after %d attempts.", retries)

        raise HpIloSendReceiveError("iLO not responding")

    def close(self):
        """Chif close function"""
        try:
            if self.fhandle is not None:
                LOGGER.debug("Calling ChifClose...")
                self.dll.ChifClose(self.fhandle)
                self.fhandle = None
        except Exception:
            pass

    def __del__(self):
        """Chif delete function"""
        self.close()
