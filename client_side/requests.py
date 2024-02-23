import logging
from random import randint
from socket import inet_aton
from secrets import token_bytes
from common.aes_cipher import AESCipher
from common.base_protocol import RequestCodesType
from common.consts import AuthRequestCodes, MessagesServerRequestCodes
from common.models import Request


class RequestFactory:
    def __init__(self, version: int, logger: logging.Logger, client_id: bytes,
                 client_name: str):
        self.version = version
        self.logger = logger
        self.client_id = client_id
        self.client_name = client_name

    def create_request(self, action: RequestCodesType, **kwargs) -> Request:
        match action:
            case AuthRequestCodes.CLIENT_REGISTRATION:
                res = self._build_auth_client_registration_request(**kwargs)
            case AuthRequestCodes.SERVER_REGISTRATION:
                res = self._build_auth_server_registration_request(**kwargs)
            case AuthRequestCodes.SERVERS_LIST:
                res = self._build_get_servers_request(**kwargs)
            case AuthRequestCodes.GET_AES_KEY:
                res = self._build_get_aes_key_request(**kwargs)
            case _:
                self.logger.error(f"Received an invalid request code to "
                                  f"construct - {action}")
                raise ValueError(f"Invalid request code to build: {action}")
        self.logger.debug(f"Successfully constructed a request for "
                          f"action '{action}': '{res}'")
        return res

    @staticmethod
    def enforce_len(data: bytes, length: int) -> bytes:
        """Ensure the byte string is exactly 'length' bytes long."""
        return data[:length].ljust(length, b'\0')

    def _build_auth_client_registration_request(self, **kwargs) -> Request:
        """ Creates a client registration request. """
        padded_name = self.enforce_len(self.client_name.encode('utf-8'), 255)
        padded_password = self.enforce_len(token_bytes(255), 255)
        payload = padded_name + padded_password
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.CLIENT_REGISTRATION,
            payload=payload
        )

    def _build_auth_server_registration_request(self, **kwargs) -> Request:
        """ Creates a server registration request. """
        padded_name = self.enforce_len(self.client_name.encode('utf-8'), 255)
        padded_aes = self.enforce_len(AESCipher.create_aes_key().encode(
            'utf-8'), 32)
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
        """ Creates a get servers request. """
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.SERVERS_LIST,
            payload=b''
        )

    def _build_get_aes_key_request(self, **kwargs) -> Request:
        """ Creates a get AES Key request based on the provided server via
        the method's kwargs. """
        if 'server_id' not in kwargs:
            raise ValueError(f"Can't create a get AES request without a "
                             f"server id.")
        padded_server_id = self.enforce_len(kwargs['server_id'], 16)
        padded_nonce = self.enforce_len(token_bytes(8), 8)
        payload = padded_server_id + padded_nonce
        # Nonce
        return Request(
            client_id=self.client_id,
            version=self.version,
            code=AuthRequestCodes.GET_AES_KEY,
            payload=payload
        )
