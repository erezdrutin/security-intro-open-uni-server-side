"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Create a factory that will create clients based on the client type.
"""
from enum import Enum
from client_side.client import Client
from client_side.consts import AUTH_SERVER_PATH
from common.consts import AuthRequestCodes, MessagesServerRequestCodes


class ClientType(Enum):
    """ Enum that holds the available types of clients that can be created. """
    MESSAGE_SERVER_FULL_FLOW = 1
    MESSAGE_SERVER_FULL_FLOW_NO_CLIENT_REGISTRATION = 2
    REGISTER_SERVER = 3
    GET_SERVERS = 4


class ClientFactory:
    def __init__(self, auth_server_path: str = AUTH_SERVER_PATH):
        self.auth_server_path = auth_server_path

    def create_client(self, option: ClientType):
        match option:
            case ClientType.MESSAGE_SERVER_FULL_FLOW:
                return self.create_full_message_server_client_flow()
            case ClientType.MESSAGE_SERVER_FULL_FLOW_NO_CLIENT_REGISTRATION:
                return self.create_msg_server_flow_no_client_registration()
            case ClientType.REGISTER_SERVER:
                return self.create_register_server_client()
            case ClientType.GET_SERVERS:
                return self.create_get_servers_client()

    def create_full_message_server_client_flow(self) -> Client:
        """
        Create a client that will act as a message server.
        @return: A client that passes through the entire auth + message
        servers flow.
        """
        return Client.initialize_client(
            auth_server_path=self.auth_server_path,
            actions=[
                AuthRequestCodes.CLIENT_REGISTRATION,
                AuthRequestCodes.SERVER_REGISTRATION,
                AuthRequestCodes.SERVERS_LIST,
                AuthRequestCodes.GET_AES_KEY,
                MessagesServerRequestCodes.AUTHENTICATE,
                MessagesServerRequestCodes.SEND_MESSAGE
            ])

    def create_msg_server_flow_no_client_registration(self) -> Client:
        """
        Create a client that will act as a message server.
        @return: A client that passes through the entire auth + message
        servers flow.
        """
        return Client.initialize_client(
            auth_server_path=self.auth_server_path,
            actions=[
                AuthRequestCodes.SERVER_REGISTRATION,
                AuthRequestCodes.SERVERS_LIST,
                AuthRequestCodes.GET_AES_KEY,
                MessagesServerRequestCodes.AUTHENTICATE,
                MessagesServerRequestCodes.SEND_MESSAGE
            ],
            me_path='me.info')

    def create_register_server_client(self) -> Client:
        """
        Create a client that will register a server.
        @return: A client that will register a server.
        """
        return Client.initialize_client(
            auth_server_path=self.auth_server_path,
            actions=[
                AuthRequestCodes.CLIENT_REGISTRATION,
                AuthRequestCodes.SERVER_REGISTRATION,
                AuthRequestCodes.SERVERS_LIST
            ])

    def create_get_servers_client(self) -> Client:
        """
        Create a client that will get the list of servers.
        @return: A client that will get the list of servers.
        """
        return Client.initialize_client(
            auth_server_path=self.auth_server_path,
            actions=[
                AuthRequestCodes.SERVERS_LIST
            ])
