"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: A file populated with constant values and enums that will be used
throughout the entire code-base.
"""
from enum import Enum

# General consts for protocol and file handling:
DEFAULT_PORT = 1256
SERVER_VERSION = 24


# Following code definitions will allow us to safely share these variables
# across the client_side, auth & messages servers:
class AuthRequestCodes(Enum):
    CLIENT_REGISTRATION = 1024
    SERVER_REGISTRATION = 1025
    SERVERS_LIST = 1026
    GET_AES_KEY = 1027
    GENERAL_ERROR = 1609
    # Not real request codes as request codes are positive integers. These
    # are mainly for BE purposes as we perform validations on client input:
    INVALID_VERSION = -1
    INVALID_CODE = -2


class AuthResponseCodes(Enum):
    REGISTRATION_SUCCESS = 1600
    REGISTRATION_FAILED = 1601
    SERVERS_LIST = 1602
    AES_KEY = 1603
    GENERAL_ERROR = 1609


class MessagesServerRequestCodes(Enum):
    AUTHENTICATE = 1028
    SEND_MESSAGE = 1029
    GENERAL_ERROR = 1609
    # Not real request codes as request codes are positive integers. These
    # are mainly for BE purposes as we perform validations on client input:
    INVALID_VERSION = -1
    INVALID_CODE = -2


class MessagesServerResponseCodes(Enum):
    AUTHENTICATE_SUCCESS = 1604
    SEND_MESSAGE_SUCCESS = 1605
    GENERAL_ERROR = 1609
