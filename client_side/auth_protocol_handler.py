import logging
import socket
from base64 import b64encode
from hashlib import sha256
from typing import Any

from client_side.consts import CLIENT_VERSION, ME_FILE_PATH
from common.aes_cipher import AESCipher
from common.consts import AuthResponseCodes, MessagesServerResponseCodes
from common.file_handler import FileHandler
from common.message_utils import unpack_server_message_headers, unpack_message
from common.models import Request, DecryptedKey, EncryptedTicket, Server, \
    EncryptedAuthenticator, DecryptedAuthenticator
from common.base_protocol import BaseProtocol
from common.utils import enforce_len


class AuthProtocolHandler(BaseProtocol):
    def __init__(self, logger: logging.Logger, client_id: bytes,
                 client_key: str, client_name: str):
        super().__init__(logger=logger, version=CLIENT_VERSION)
        self.client_id = client_id
        self.client_name = client_name
        self.client_key = client_key
        self.shared_aes_key = None

    @staticmethod
    def make_request(client_socket: socket.socket, request: Request) -> None:
        """ Receives a socket to pass messages through and makes a request. """
        bytes_res = request.to_bytes()
        client_socket.sendall(bytes_res)

    def handle_incoming_message(self, client_socket: socket, **kwargs) -> Any:
        """
        Handles an incoming request from client side.
        @param client_socket: A socket we can pass messages through.
        @return: Returns the result of the handler's execution.
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
        """ In case of successful client / server registration - log the
        success and continue to handle the next method. """
        self.logger.info(f"Successfully registered to auth server with "
                         f"request: {request}")
        if not self.client_id:
            # Generated a new client id, we would probably want to store
            # this as a "me.info" file:
            self.client_id = request.payload
            file_content = "\n".join([
                self.client_name,
                b64encode(request.payload).decode('utf-8')
            ])
            FileHandler(ME_FILE_PATH, logger=self.logger).write_value(
                file_content)
        return request

    @BaseProtocol.register_request(AuthResponseCodes.REGISTRATION_FAILED)
    def _handle_registration_failure(self, client_socket: socket,
                                     request: Request) -> Request:
        self.logger.error(f"Failed to register to auth server with "
                          f"request: {request}")
        return request

    @BaseProtocol.register_request(AuthResponseCodes.SERVERS_LIST)
    def _handle_servers_list(self, client_socket: socket,
                             request: Request) -> Request:
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
        # Do something with all the provided crap ffs:
        self.logger.info(f"Successfully fetched AES / Ticket keys from auth "
                         f"server: {request.payload}")

        if not request.payload[0:16] == self.client_id:
            raise ValueError(f"Received invalid client id in payload!")

        # DECRYPT key from request
        # encrypted_key_iv = request.payload[17:33]
        # cipher = AESCipher(key=self.client_key, iv=encrypted_key_iv)
        cipher_key = sha256(
            enforce_len(self.client_key.encode('utf-8'), 255)).digest()
        decrypted_key = DecryptedKey.from_bytes(
            request.payload[16:112], cipher_key=cipher_key.hex())
        self.shared_aes_key = decrypted_key.decrypted_aes
        print(f"DECRYPTED NONCE: {decrypted_key.decrypted_nonce}")
        # ticket = DecryptedTicket.from_bytes(
        #     data=request.payload[128:], cipher=shared_cipher)

        ticket = EncryptedTicket.from_bytes(request.payload[112:])
        shared_cipher = AESCipher(self.shared_aes_key.decode(),
                                       iv=decrypted_key.shared_iv)
        print(f"TICKET STUFF:\nVERSION: {ticket.version}\n"
              f"CLIENT_ID: {ticket.client_id}\nSERVER_ID: {ticket.server_id}\n"
              f"CREATION_TIME: {ticket.creation_time}\nSHARED_IV: "
              f"{ticket.ticket_iv}\nENC_AES_KEY: {ticket.encrypted_aes_key}\n"
              f"ENC_TICKET_TTL: {ticket.encrypted_expiration_time}")

        authenticator = EncryptedAuthenticator.create(
            version=request.version, client_id=request.client_id,
            server_id=ticket.server_id, creation_time=ticket.creation_time,
            shared_iv=ticket.ticket_iv, cipher=shared_cipher
        )

        decrypted_auth = DecryptedAuthenticator.from_bytes(
            authenticator.to_bytes(), cipher=shared_cipher)

        request.payload = authenticator.to_bytes() + request.payload[112:]
        print(request.payload)
        return request

        # Construct an Authenticator and pass the Ticket "as is":
        # 1. 16 Bytes - Client ID, can be dropped
        # 2."Encrypted Key": ClientID (16) + enc_Nonce (16) + enc_AES (48).
        # 3. "Ticket": All after #2, pass "as is".

        # Focus on #2 for a sec (bits 16-...):
        # 1. 16-32: IV --> create a cypher using this client password hash.
        # 2. 32-48: Nonce --> Decrypt Nonce using the cypher.
        # 3. 48-96: AES --> Decrypt "new" AES key.

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.AUTHENTICATE_SUCCESS)
    def _handle_success_msg_server_auth(self, client_socket: socket,
                                        request: Request) -> Request:
        self.logger.info(b64encode(request.payload).decode())
        return request

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.SEND_MESSAGE_SUCCESS)
    def _handle_success_msg_server_auth(self, client_socket: socket,
                                        request: Request) -> Request:
        self.logger.info(b64encode(request.payload).decode())
        return request

    @BaseProtocol.register_request(
        MessagesServerResponseCodes.GENERAL_ERROR)
    def _handle_error_msg_server(self, client_socket: socket,
                                 request: Request) -> Request:
        self.logger.error(f"Received invalid status from messages server for"
                          f"the last request. Error - "
                          f"{b64encode(request.payload).decode()}")
        return request
