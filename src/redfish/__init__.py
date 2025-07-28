""" Redfish restful library """

__all__ = ["rest", "ris", "hpilo"]
__version__ = "6.2.0.0"

import logging

from redfish.rest.v1 import AuthMethod, LegacyRestClient, RedfishClient


def redfish_logger(file_name, log_format, log_level=logging.ERROR):
    """redfish logger"""
    formatter = logging.Formatter(log_format)
    fhdl = logging.FileHandler(file_name)
    fhdl.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fhdl)
    logger.setLevel(log_level)
    return logger
