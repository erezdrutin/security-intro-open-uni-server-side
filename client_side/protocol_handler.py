"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Act as the protocol used by the client to communicate with the
different servers (auth/messages). The protocol defines how the client is
expected to behave based on different request codes passed by the servers.
"""
import logging
import socket
from base64 import b64encode
from hashlib import sha256
from secrets import token_bytes
from typing import Any
from client_side.consts import CLIENT_VERSION, ME_FILE_PATH
from common.aes_cipher import AESCipher
from common.consts import AuthResponseCodes, MessagesServerResponseCodes
from common.file_handler import FileHandler
from common.message_utils import unpack_server_message_headers, unpack_message
from common.models import Request, DecryptedKey, EncryptedTicket, Server, \
    EncryptedAuthenticator
from common.base_protocol import BaseProtocol
from common.utils import enforce_len


class ProtocolHandler(BaseProtocol):
    def __init__(self, logger: logging.Logger, client_id: bytes,
                 client_key: str, client_name: str):
        """
        Initialize the protocol handler.
        @param logger: A logger to use.
        @param client_id: The client's id.
        @param client_key: The client's key.
        @param client_name: The client's name.
        """
        super().__init__(logger=logger, version=CLIENT_VERSION)
        self.client_id = client_id
        self.client_name = client_name
        self.client_key = client_key
        self.shared_aes_key = None
        self.nonce = token_bytes(8)
        # Debug logging the nonce for easier offline attack testing:
        self.logger.debug(f"Created nonce: {self.nonce}")

    @staticmethod
    def make_request(client_socket: socket.socket, request: Request) -> None:
        """
        Sends a request to the server.
        @param client_socket: A socket we can pass messages through.
        @param request: The request to send.
        """
        bytes_res = request.to_bytes()
        client_socket.sendall(bytes_res)

    def handle_incoming_message(self, client_socket: socket, **kwargs) -> Any:
        """
        Handle an incoming message from the server.
        @param client_socket: The client's socket.
        @param kwargs: Additional arguments.
        @return: The response to the message, after being handled via one of
        the handlers defined below.
        """
        version, code, payload_size = unpack_server_message_headers(
            client=client_socket)

        if 'codes_type' not in kwargs:
            codes_type = AuthResponseCodes
            logging.warning(f"Didn't get a request codes type, assuming "
                            f"'{type(codes_type)}'...")
        else:
            codes_type = kwargs['codes_type']

        request, handler = unpack_message(
            client=client_socket, client_id=self.client_id, code=code,
            codes=codes_type, payload_size=payload_size,
            request_handlers=self.request_handlers, version=version,
            accepted_version=self.version)
        handler = self.log_decorator(handler)
        return handler(client_socket, request)

    @BaseProtocol.register_request(AuthResponseCodes.REGISTRATION_SUCCESS)
    def _handle_registration_success(self, client_socket: socket,
                                     request: Request) -> Request:
        """
        Handle a successful registration to the auth server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.info(f"Successfully registered to auth server with "
                         f"request: {request}")
        if not self.client_id:
            # Generated a new client id, we would probably want to store
            # this as a "me.info" file:
            self.client_id = request.payload
            file_content = "\n".join([
                self.client_name,
                b64encode(request.payload).decode('utf-8'),
                self.client_key
            ])
            FileHandler(ME_FILE_PATH, logger=self.logger).write_value(
                file_content)
        return request

    @BaseProtocol.register_request(AuthResponseCodes.REGISTRATION_FAILED)
    def _handle_registration_failure(self, client_socket: socket,
                                     request: Request):
        """
        Handle a failed registration to the auth server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.error(f"Failed to register to auth server with "
                          f"request: {request}")
        raise Exception(f"Client already registered, finishing execution...")

    @BaseProtocol.register_request(AuthResponseCodes.SERVERS_LIST)
    def _handle_servers_list(self, client_socket: socket,
                             request: Request) -> Request:
        """
        Handle a list of servers received from the auth server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.info(f"Successfully received servers list from auth "
                         f"server...")
        servers = Server.bytes_to_servers(payload=request.payload,
                                          version=self.version)
        server = Server.select_server(servers=servers)
        # Overriding the request's payload with the selected server:
        request.payload = server.to_bytes()
        return request

    @BaseProtocol.register_request(AuthResponseCodes.AES_KEY)
    def _handle_get_aes_key(self, client_socket: socket,
                            request: Request) -> Request:
        """
        Handles the AES key retrieval request by decrypting the encrypted key
        and ticket from the request payload. Validates the client ID and nonce
        in the process. Modifies the request payload with the decrypted
        authenticator and encrypted ticket for further processing.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        client_bytes = request.payload[0:16]
        encrypted_key_bytes = request.payload[16:112]
        encrypted_ticket_bytes = request.payload[112:]
        # If for some reason we received a different client - throw an error:
        if not client_bytes == self.client_id:
            raise ValueError(f"Received invalid client id in payload!")

        # Decrypt the "Encrypted Key" from the request:
        cipher_key = sha256(
            enforce_len(self.client_key.encode('utf-8'), 255)).digest()
        decrypted_key = DecryptedKey.from_bytes(
            encrypted_key_bytes, cipher_key=cipher_key.hex())
        self.shared_aes_key = decrypted_key.decrypted_aes

        # If for some reason the nonce is invalid - throw an error:
        if decrypted_key.decrypted_nonce != self.nonce:
            err_msg = f"Received an invalid nonce from server! Expected " \
                      f"nonce: {self.nonce}, received nonce: " \
                      f"{decrypted_key.decrypted_nonce}"
            self.logger.error(err_msg)
            raise ValueError(err_msg)

        # Create an encrypted ticket and an authenticator based on payload:
        ticket = EncryptedTicket.from_bytes(encrypted_ticket_bytes)
        authenticator_iv = AESCipher.create_iv()
        shared_cipher = AESCipher(self.shared_aes_key.decode(),
                                  iv=authenticator_iv)
        authenticator = EncryptedAuthenticator.create(
            version=request.version, client_id=request.client_id,
            server_id=ticket.server_id, creation_time=ticket.creation_time,
            shared_iv=authenticator_iv, cipher=shared_cipher
        )

        # concatenate the payload and return for further processing:
        request.payload = authenticator.to_bytes() + encrypted_ticket_bytes
        return request

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.AUTHENTICATE_SUCCESS)
    def _handle_success_msg_server_auth(self, client_socket: socket,
                                        request: Request) -> Request:
        """
        Handle a successful authentication with the Messages Server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.info(
            "Managed to successfully authenticate with Messages Server.")
        return request

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.SEND_MESSAGE_SUCCESS)
    def _handle_success_msg_server_auth(self, client_socket: socket,
                                        request: Request) -> Request:
        """
        Handle a successful message sent to the Messages Server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.info("Managed to successfully send a message to the "
                         "Messages Server and received a valid response.")
        return request

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.GENERAL_ERROR)
    def _handle_error_msg_server(self, client_socket: socket,
                                 request: Request) -> Request:
        """
        Handle a general error from the Messages Server.
        @param client_socket: The client's socket.
        @param request: The request.
        @return: The request, after (potentially) modifying its payload for
        further processing.
        """
        self.logger.error(f"Received invalid status from messages server for"
                          f"the last request. Error - "
                          f"{request.payload.decode('utf-8')}")
        return request
