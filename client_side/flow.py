"""
Author: Erez Drutin
Date: 10.03.2024
Purpose: The idea here is to define various "flows" that the client can run.
Each flow has a different purpose and will lead to a different behaviour.
"""
from typing import List, Union
from common.consts import AuthRequestCodes, MessagesServerRequestCodes

requests_type = Union[AuthRequestCodes, MessagesServerRequestCodes]


def client_auth_server_flow() -> List[requests_type]:
    return [
        AuthRequestCodes.CLIENT_REGISTRATION,
        # AuthRequestCodes.SERVER_REGISTRATION,
        AuthRequestCodes.SERVERS_LIST,
        AuthRequestCodes.GET_AES_KEY,
        MessagesServerRequestCodes.AUTHENTICATE,
        MessagesServerRequestCodes.SEND_MESSAGE
    ]
    ...


def msg_server_registration_flow() -> List[requests_type]:
    ...


def msg_server_client_flow() -> List[requests_type]:
    """
    Consists of registering a server, requires current user to be registered.
    @return:
    """
    return [
        AuthRequestCodes.SERVER_REGISTRATION
    ]
    ...
