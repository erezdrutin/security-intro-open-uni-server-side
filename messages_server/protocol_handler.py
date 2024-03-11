import logging
import socket
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from typing import Any, Dict
from hashlib import sha256
from uuid import uuid4
from messages_server.consts import SERVER_VERSION, RequestCodes, ResponseCodes
from common.aes_cipher import AESCipher
from common.consts import MessagesServerRequestCodes
from common.db_handler import DatabaseHandler
from common.models import Request, Response, Client, Server, EncryptedKey, \
    EncryptedTicket, DecryptedTicket, DecryptedKey, DecryptedAuthenticator, \
    EncryptedAuthenticator, ClientMessage
from common.base_protocol import BaseProtocol
from common.message_utils import unpack_client_message_headers, unpack_message
from common.utils import enforce_len, dt_with_ttl_to_ts


class ProtocolHandler(BaseProtocol):
    def __init__(self, db_handler: DatabaseHandler, logger: logging.Logger,
                 server: Server):
        super().__init__(logger=logger, version=SERVER_VERSION)
        self.db_handler = db_handler
        self.server = server
        self.tickets: Dict[bytes, DecryptedTicket] = {}

    def handle_incoming_message(self, client_socket: socket, **kwargs) -> Any:
        """
        Handles an incoming request from client side.
        @param client_socket: A socket we can pass messages through.
        @return: Returns the result of the handler's execution.
        """
        client_id, version, code, payload_size = unpack_client_message_headers(
            client=client_socket)

        request, handler = unpack_message(
            client=client_socket, client_id=client_id, code=code,
            codes=MessagesServerRequestCodes, payload_size=payload_size,
            request_handlers=self.request_handlers, version=version,
            accepted_version=self.version)
        handler = self.log_decorator(handler)
        return handler(client_socket, request)

    @BaseProtocol.register_request(RequestCodes.AUTHENTICATE)
    def _handle_client_authentication(self, client_socket: socket.socket,
                                      request: Request) -> None:
        # Extract authenticator / ticket from request:
        authenticator_bytes = request.payload[0:112]
        ticket_bytes = request.payload[112:]

        # Decrypt ticket from request:
        enc_ticket = EncryptedTicket.from_bytes(data=ticket_bytes)
        server_cipher = AESCipher(self.server.aes_key.hex(),
                                  iv=enc_ticket.ticket_iv)
        ticket = DecryptedTicket.from_bytes(enc_ticket.to_bytes(),
                                            cipher=server_cipher)

        self.tickets[ticket.client_id] = ticket
        self.logger.debug(f"successfully decrypted ticket: {ticket}")

        # Decrypt authenticator from request:
        shared_cipher = AESCipher(ticket.decrypted_aes_key.decode(),
                                  iv=ticket.ticket_iv)
        authenticator = DecryptedAuthenticator.from_bytes(
            data=authenticator_bytes, cipher=shared_cipher)
        self.logger.debug(f"successfully decrypted auth: {authenticator}")

        # Handle invalid ticket-authenticator combination:
        is_creation_time_valid = authenticator.creation_time <= \
                                 ticket.decrypted_expiration_time
        is_client_id_valid = authenticator.client_id == ticket.client_id
        is_server_id_valid = authenticator.server_id == ticket.server_id
        is_version_valid = authenticator.version == ticket.version
        if not (is_creation_time_valid and is_client_id_valid and
                is_server_id_valid and is_version_valid):
            # INVALID REQUEST - return status 1609
            response = Response(
                version=authenticator.version,
                code=ResponseCodes.GENERAL_ERROR,
                payload=b'Invalid authenticator/ticket, please try again.')
        else:
            # Otherwise, we have a VALID RESPONSE:
            response = Response(
                version=authenticator.version,
                code=ResponseCodes.AUTHENTICATE_SUCCESS,
                payload=b'Successfully authenticated!')

        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    @BaseProtocol.register_request(RequestCodes.SEND_MESSAGE)
    def _handle_client_message(self, client_socket: socket.socket,
                               request: Request) -> None:
        try:
            message = ClientMessage.from_bytes(
                data=request.payload,
                aes_key=self.tickets[request.client_id].decrypted_aes_key
            ).decode('utf-8')
            self.logger.info(f"Successfully received and interpreted message "
                             f"from client '{request.client_id}': {message}")

            # Otherwise, we have a VALID RESPONSE:
            response = Response(
                version=request.version,
                code=ResponseCodes.SEND_MESSAGE_SUCCESS,
                payload=b'Successfully received and interpreted message!')
        except Exception as e:
            err_msg = f'Unable to interpret message from client. Error: {e}'
            self.logger.error(err_msg)
            response = Response(
                version=request.version,
                code=ResponseCodes.GENERAL_ERROR,
                payload=err_msg.encode('utf-8')
            )

        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)
