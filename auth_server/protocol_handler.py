"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Act as the protocol used by the authentication server to
communicate with clients. The protocol defines how the auth server is
expected to behave based on different request codes passed by users.
"""
import logging
import socket
from datetime import datetime
from typing import Any
from hashlib import sha256
from uuid import uuid4
from auth_server.consts import SERVER_VERSION, RequestCodes, ResponseCodes, \
    TICKET_TTL_SEC
from common.aes_cipher import AESCipher
from common.consts import AuthRequestCodes
from common.db_handler import DatabaseHandler
from common.models import Request, Response, Client, Server, EncryptedKey, \
    EncryptedTicket
from common.base_protocol import BaseProtocol
from common.message_utils import unpack_client_message_headers, unpack_message


class ProtocolHandler(BaseProtocol):
    def __init__(self, db_handler: DatabaseHandler, logger: logging.Logger):
        super().__init__(logger=logger, version=SERVER_VERSION)
        self.db_handler = db_handler

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
            codes=AuthRequestCodes, payload_size=payload_size,
            request_handlers=self.request_handlers, version=version,
            accepted_version=self.version)
        handler = self.log_decorator(handler)
        return handler(client_socket, request)

    @BaseProtocol.register_request(RequestCodes.CLIENT_REGISTRATION)
    def _handle_client_registration(self, client_socket: socket.socket,
                                    request: Request) -> None:
        """
        Registers a new client based on the provided request information.
        @param client_socket: A socket for communication with the client.
        @param request: A Request object containing the registration details.
        """
        # Extract name & password from the payload, apply sha256 on password:
        client_name = request.payload[:255].rstrip(b'\0').decode('utf-8')
        client_password = sha256(request.payload[255:510]).digest()
        # Generate a 16 bit UUID for the client:
        client_id = uuid4().bytes

        # Check if client already exists in the DB:
        client_exists = self.db_handler.get_client_by_name(name=client_name)
        if client_exists:
            response = Response(self.version,
                                ResponseCodes.REGISTRATION_FAILED, b"")
            client_socket.sendall(response.to_bytes())
            return

        # Register the new client in the DB:
        db_res = self.db_handler.add_client(client=Client(
            id=client_id,
            name=client_name,
            password_hash=client_password,
            last_seen=datetime.now()
        ))

        if not db_res:
            response = Response(
                version=self.version, code=ResponseCodes.REGISTRATION_FAILED,
                payload=b'')
        else:
            response = Response(
                version=self.version, code=ResponseCodes.REGISTRATION_SUCCESS,
                payload=client_id)

        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    @BaseProtocol.register_request(RequestCodes.SERVER_REGISTRATION)
    def _handle_server_registration(self, client_socket: socket.socket,
                                    request: Request) -> None:
        """
        Registers a new server based on the provided request information.
        @param client_socket: A socket for communication with the client.
        @param request: A Request object containing the registration details.
        """
        # Extract name & password from the payload, apply sha256 on password:
        server_name = request.payload[:255].rstrip(b'\0').decode('utf-8')
        aes_key = request.payload[255:287]
        server_ip = socket.inet_ntoa(request.payload[287:291])
        server_port = int.from_bytes(request.payload[291:293], "big")
        # Generate a 16 bit UUID for the client:
        server_id = uuid4().bytes
        # Register new server in DB
        server = Server(
            id=server_id,
            name=server_name,
            ip=server_ip,
            port=server_port,
            aes_key=aes_key,
            version=request.version
        )
        self.logger.info(f"Registering a new messages server - {server}")
        db_res = self.db_handler.add_server(server=server)

        if not db_res:
            response = Response(
                version=self.version, code=ResponseCodes.REGISTRATION_FAILED,
                payload=b'')
        else:
            logging.info(f"successfully registered server id {server_id}")
            response = Response(
                version=self.version, code=ResponseCodes.REGISTRATION_SUCCESS,
                payload=server_id)

        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    @BaseProtocol.register_request(RequestCodes.SERVERS_LIST)
    def _handle_servers_list(self, client_socket: socket.socket,
                             request: Request) -> None:
        """
        Retrieves and sends a list of servers to the client.
        @param client_socket: A socket for communication with the client.
        @param request: A Request object containing the registration details.
        """
        db_res = self.db_handler.get_servers()
        if db_res:
            payload = b''.join(res.to_bytes() for res in db_res)
            response = Response(
                version=self.version, code=ResponseCodes.SERVERS_LIST,
                payload=payload)
        else:
            # Return an empty servers list
            response = Response(
                version=self.version, code=ResponseCodes.SERVERS_LIST,
                payload=b'')

        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    @BaseProtocol.register_request(RequestCodes.GET_AES_KEY)
    def _handle_get_aes(self, client_socket: socket.socket,
                        request: Request) -> None:
        """
        Generates and sends a shared AES key, encrypted key, and ticket to
        the client.
        @param client_socket: A socket for communication with the client.
        @param request: A Request object containing the registration details.
        """
        shared_aes_key = AESCipher.create_aes_key()
        server_id = request.payload[:16]
        nonce = request.payload[16:24]

        # Encrypted key construction (with client key):
        encrypted_key_iv = AESCipher.create_iv()
        client = self.db_handler.get_client_by_id(_id=request.client_id)
        cipher = AESCipher(client.password_hash.hex(), encrypted_key_iv)
        encrypted_key = EncryptedKey.create(
            shared_iv=encrypted_key_iv, shared_aes_key=shared_aes_key,
            nonce=nonce, cipher=cipher)

        # Ticket construction (with messages server key):
        ticket_iv = AESCipher.create_iv()
        server = self.db_handler.get_server_by_id(server_id=server_id)
        cipher = AESCipher(server.aes_key.hex(), iv=ticket_iv)
        creation_time = datetime.now()
        ticket = EncryptedTicket.create(
            version=self.version, client_id=request.client_id,
            server_id=server.id, creation_time=creation_time,
            shared_iv=ticket_iv, aes_key=shared_aes_key,
            ticket_ttl_sec=TICKET_TTL_SEC, cipher=cipher)

        # Construct the response and send it back to the client:
        payload = request.client_id + encrypted_key.to_bytes() \
                  + ticket.to_bytes()
        response = Response(version=self.version, code=ResponseCodes.AES_KEY,
                            payload=payload)
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)
