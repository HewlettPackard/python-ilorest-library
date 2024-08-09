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
            self.dll.enabledebugoutput.argtypes = [c_char_p]
            if log_dir is not None:
                logdir_c = create_string_buffer(log_dir.encode('UTF-8'))
                self.dll.enabledebugoutput(logdir_c)

        self.dll.ChifInitialize(None)

        self.dll.ChifCreate.argtypes = [c_void_p]
        self.dll.ChifCreate.restype = c_uint32

        try:
            LOGGER.debug("Calling ChifCreate...")
            status = self.dll.ChifCreate(byref(fhandle))
            if status != BlobReturnCodes.SUCCESS:
                raise HpIloInitialError("Error %s occurred while trying " "to create a channel." % status)

            self.fhandle = fhandle

            if "skip_ping" not in os.environ:
                status = self.dll.ChifPing(self.fhandle)
                if status != BlobReturnCodes.SUCCESS:
                    errmsg = "Error {0} occurred while trying to open a " "channel to iLO".format(status)
                    if status == BlobReturnCodes.CHIFERR_NoDriver:
                        errmsg = "No devices were found."
                        if os.name != "nt":
                            errmsg = f"{errmsg} Ensure the hpilo kernel module is loaded."
                    elif status == BlobReturnCodes.CHIFERR_AccessDenied:
                        errmsg = "You must be root/Administrator to use this program."
                    raise HpIloInitialError(errmsg)
                # LOGGER.debug("Calling ChifSetRecvTimeout...")
                self.dll.ChifSetRecvTimeout(self.fhandle, 60000)
        except:
            raise

    def chif_packet_exchange(self, data):
        """Function for handling chif packet exchange

        :param data: data to be sent for packet exchange
        :type data: str

        """
        datarecv = self.dll.get_max_buffer_size()
        buff = create_string_buffer(bytes(data))

        recbuff = create_string_buffer(datarecv)
        # LOGGER.debug("Calling ChifPacketExchange...")
        error = self.dll.ChifPacketExchange(self.fhandle, byref(buff), byref(recbuff), datarecv)
        if error != BlobReturnCodes.SUCCESS:
            raise HpIloChifPacketExchangeError("Error %s occurred while " "exchange chif packet" % error)

        pkt = bytearray()

        if datarecv is None:
            bytearray(recbuff[:])
        else:
            pkt = bytearray(recbuff[:datarecv])

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

        while tries < retries:
            try:
                resp = self.chif_packet_exchange(data)

                if sequence != struct.unpack("<H", bytes(resp[2:4]))[0]:
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug("Attempt %s has a bad sequence number.\n", tries + 1)
                    continue

                return resp
            except Exception as excp:
                time.sleep(1)

                if tries == (retries - 1):
                    self.close()

                    if LOGGER.isEnabledFor(logging.DEBUG) and excp:
                        LOGGER.debug("Error while reading iLO: %s", str(excp))
                    raise excp

            tries += 1

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
