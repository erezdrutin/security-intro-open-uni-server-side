import logging
import socket
from base64 import b64encode
from typing import Any

from auth_server.consts import ResponseCodes
from client_side.consts import CLIENT_VERSION
from common.consts import AuthRequestCodes, AuthResponseCodes
from common.file_handler import FileHandler
from common.message_utils import unpack_server_message_headers, unpack_message
from common.models import Request, Response
from common.base_protocol import BaseProtocol


class AuthProtocolHandler(BaseProtocol):
    def __init__(self, logger: logging.Logger, client_id: bytes,
                 client_name: str):
        super().__init__(logger=logger, version=CLIENT_VERSION)
        self.client_id = client_id
        self.client_name = client_name

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

    @BaseProtocol.register_request(ResponseCodes.REGISTRATION_SUCCESS)
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
            FileHandler("me.info", logger=self.logger).write_value(file_content)
        return request

    @BaseProtocol.register_request(ResponseCodes.REGISTRATION_FAILED)
    def _handle_registration_failure(self, client_socket: socket,
                                     request: Request) -> Request:
        self.logger.info(f"Failed to register to auth server with "
                         f"request: {request}")
        return request

    @BaseProtocol.register_request(ResponseCodes.SERVERS_LIST)
    def _handle_servers_list(self, client_socket: socket,
                             request: Request) -> Request:
        self.logger.info(f"Successfully received servers list from auth "
                         f"server: {request.payload}")
        print(request.payload)
        return request

    @BaseProtocol.register_request(ResponseCodes.AES_KEY)
    def _handle_get_aes_key(self, client_socket: socket,
                            request: Request) -> Request:
        self.logger.info(f"Successfully fetched AES / Ticket keys from auth "
                         f"server: {request.payload}")
        print(request.payload)
        return request
