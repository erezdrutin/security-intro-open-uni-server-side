"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Define all available requests that can be created by the client.
"""
import logging
from random import randint
from socket import inet_aton
from common.aes_cipher import AESCipher
from common.base_protocol import RequestCodesType
from common.consts import AuthRequestCodes, MessagesServerRequestCodes
from common.models import Request
from common.utils import enforce_len


class RequestFactory:
    def __init__(self, version: int, logger: logging.Logger, client_id: bytes,
                 client_name: str, client_password: str):
        """
        Initializes a new RequestFactory.
        @param version: The version of the request.
        @param logger: A logger to use for logging.
        @param client_id: A client id to use for requests.
        @param client_name: A client name to pass in requests.
        @param client_password: A client password to pass in requests
        """
        self.version = version
        self.logger = logger
        self.client_id = client_id
        self.client_name = client_name
        self.client_password = client_password

    def create_request(self, action: RequestCodesType, **kwargs) -> Request:
        """
        Creates a request based on the provided action and kwargs.
        @param action: The action to perform.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        match action:
            case AuthRequestCodes.CLIENT_REGISTRATION:
                res = self._build_auth_client_registration_request(**kwargs)
            case AuthRequestCodes.SERVER_REGISTRATION:
                res = self._build_auth_msg_server_registration_request(
                    **kwargs)
            case AuthRequestCodes.SERVERS_LIST:
                res = self._build_get_servers_request(**kwargs)
            case AuthRequestCodes.GET_AES_KEY:
                res = self._build_get_aes_key_request(**kwargs)
            case MessagesServerRequestCodes.AUTHENTICATE:
                res = self._build_authenticate_msg_server_request(**kwargs)
            case MessagesServerRequestCodes.SEND_MESSAGE:
                res = self._build_send_message_to_msg_server_request(**kwargs)
            case _:
                self.logger.error(f"Received an invalid request code to "
                                  f"construct - {action}")
                raise ValueError(f"Invalid request code to build: {action}")
        self.logger.debug(f"Successfully constructed a request for "
                          f"action '{action}': '{res}'")
        return res

    def _build_auth_client_registration_request(self, **kwargs) -> Request:
        """
        Creates a client registration request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        padded_name = enforce_len(self.client_name.encode('utf-8'), 255)
        padded_password = enforce_len(self.client_password.encode('utf-8'),
                                      255)
        # Construct payload & request:
        payload = padded_name + padded_password
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.CLIENT_REGISTRATION,
            payload=payload
        )

    def _build_auth_msg_server_registration_request(self, **kwargs) -> Request:
        """
        Creates a message server registration request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        padded_name = enforce_len(self.client_name.encode('utf-8'), 255)
        padded_aes = enforce_len(AESCipher.create_aes_key().encode('utf-8'),
                                 32)
        ip_bytes = inet_aton('0.0.0.0')
        port_bytes = randint(1000, 9999).to_bytes(2, byteorder='big')
        payload = padded_name + padded_aes + ip_bytes + port_bytes
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.SERVER_REGISTRATION,
            payload=payload
        )

    def _build_get_servers_request(self, **kwargs) -> Request:
        """
        Creates a get servers request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.SERVERS_LIST,
            payload=b''
        )

    def _build_get_aes_key_request(self, **kwargs) -> Request:
        """
        Creates a get AES key request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        if any(key not in kwargs for key in ['server_id', 'nonce']):
            raise ValueError(f"Can't create a get AES request without a "
                             f"server id / nonce.")
        padded_server_id = enforce_len(kwargs['server_id'], 16)
        padded_nonce = enforce_len(kwargs['nonce'], 8)
        payload = padded_server_id + padded_nonce
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.GET_AES_KEY,
            payload=payload
        )

    def _build_authenticate_msg_server_request(self, **kwargs) -> Request:
        """
        Builds "AUTHENTICATE" msg server request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        if 'payload' not in kwargs:
            msg = "Can't authenticate with Messages Server without a payload"
            self.logger.error(msg)
            raise ValueError(msg)
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=MessagesServerRequestCodes.AUTHENTICATE,
            payload=kwargs['payload']
        )

    def _build_send_message_to_msg_server_request(self, **kwargs) -> Request:
        """
        Builds "SEND_MESSAGE" msg server request.
        @param kwargs: Additional arguments to pass to the request.
        @return: A constructed Request.
        """
        if 'payload' not in kwargs:
            msg = "Can't send a message to Messages Server without user input"
            self.logger.error(msg)
            raise ValueError(msg)
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=MessagesServerRequestCodes.SEND_MESSAGE,
            payload=kwargs['payload']
        )

