"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: The "main" logic in the messages_server code. This file contains the
implementation for the Protocol as depicted in Maman 15. Normally,
this would be separated into multiple files. However, given the requirement
of passing only the .py files, I figured it would be "easier" to follow
along via a single file without starting to divide functionality across
various utility classes and methods.
In any case, the Protocol Handler has a handle_request method that is
triggered whenever data is received from the client_side. The method then
extracts the relevant data from the request and matches it to the
appropriate handler (if valid, otherwise will match it to an error handler).
Each handler in the Protocol is "marked" (wrapped) with its RequestCode,
thus allowing for easy interpretation, maintenance and addition of new codes.
"""

import logging
import os
import socket
import uuid
import struct
from datetime import datetime
from const import SERVER_VERSION, RequestCodes, ResponseCodes, \
    CLIENTS_NAME_SIZE, CLIENTS_AES_KEY_SIZE, FILES_STORAGE_FOLDER
from common.custom_exceptions import ClientDisconnectedError
from common.db_handler import DatabaseHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from crypto import readfile as readfile_crc32, decrypt_aes_cbc
from common.file_handler import FileHandler
from common.models import Client, File, Request, Response
from common.base_protocol import BaseProtocol


class ProtocolHandler(BaseProtocol):
    def __init__(self, db_handler: DatabaseHandler, logger: logging.Logger):
        super().__init__(logger=logger)
        self.SERVER_VERSION = SERVER_VERSION
        self.db_handler = db_handler

    def handle_incoming_message(self, client_socket: socket.socket) -> None:
        """
        Handles an incoming request from a client_side. The method first
        processes the initial bytes from a request to determine the client_side
        ID, version, code and size of the payload. Then, based on the
        payload size, it reads the rest of the payload and executes the
        request with the appropriate handler function. If the client_side has
        disconnected abruptly, the method will raise ClientDisconnectedError.
        @param client_socket: A socket we can pass messages through.
        """
        # The format string for struct.unpack:
        # - 16s: client_id is a 16-byte string
        # - B: version is a 1-byte unsigned char
        # - H: code is a 2-byte unsigned short
        # - I: payload_size is a 4-byte unsigned int
        # Assuming the total size of the struct is:
        # (16 + 1 + 2 + 4 = 23 bytes) without the payload.
        format_string = "16sBHI"
        size_without_payload = struct.calcsize(format_string)
        data = client_socket.recv(size_without_payload)

        # The client_side has disconnected, raise an error
        if data == b'':
            raise ClientDisconnectedError("Client has disconnected.")

        # Unpack the data
        client_id_bytes, version_byte, code, payload_size = struct.unpack(
            format_string, data)
        # Save client_id as bytes and remove trailing null bytes
        client_id = client_id_bytes.replace(b'\x00', b'')
        version = chr(version_byte)  # Converts ascii byte value to string

        try:
            code = RequestCodes(code)
        except ValueError:
            code = RequestCodes.INVALID_CODE

        # Read the payload based on the payload_size
        payload = client_socket.recv(payload_size)

        request = Request(client_id, version, code,
                          payload_size, payload)

        # Trigger handler based on request code + wrap with logger:
        if version != SERVER_VERSION:
            handler = self.request_handlers[RequestCodes.INVALID_VERSION]
        elif request.code not in self.request_handlers:
            handler = self.request_handlers[RequestCodes.INVALID_CODE]
        else:
            handler = self.request_handlers[request.code]
        handler = self.log_decorator(handler)
        handler(client_socket, request)

    @BaseProtocol.register_request(RequestCodes.REGISTRATION)
    def _handle_registration(self, client_socket: socket.socket,
                             request: Request) -> None:
        """
        Handles a registration request from a client_side. We first check if the
        client_side already exists in the DB, in which case we will send a
        REGISTRATION_FAILED response. Otherwise, creating the new client_side
        record in the DB and returns generated 16 bit clientId to the Client.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        # Extracting request details
        client_name = request.payload.decode('utf-8').strip('\x00').strip()

        client = self.db_handler.get_client(client_name=client_name)
        if client:
            # client_side already exists
            response = Response(self.SERVER_VERSION,
                                ResponseCodes.REGISTRATION_FAILED, b"")
            client_socket.sendall(response.to_bytes())
            return

        # Generating a 16 bit UUID for the client_side:
        client_id = uuid.uuid4().bytes
        client = Client(id=client_id, name=client_name, public_key=b'',
                        last_seen=datetime.now(), aes_key=b'')

        # Add the client_side to the DB (with partial info):
        self.db_handler.add_client(client=client)

        # Craft the response payload with the UUID
        response = Response(self.SERVER_VERSION,
                            ResponseCodes.REGISTRATION_SUCCESS, client_id)
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    @BaseProtocol.register_request(RequestCodes.RECONNECT)
    def _handle_reconnect(self, client_socket: socket.socket,
                          request: Request) -> None:
        """
        Handle a reconnection request from a client_side. We first check if the
        client_side doesn't exist yet or if it doesn't have a public key
        generated, in which case we will return a RECONNECT_REJECTED
        response. Otherwise, encrypting, saving in the DB and sending the AES
        key to the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        # Extracting request details
        client_name = request.payload.decode('utf-8').strip('\x00').strip()

        # Extract client_side details and update last seen in DB:
        client = self.db_handler.get_client(client_name=client_name)
        self.db_handler.update_client_last_seen(client_id=client.id)
        if not client or not client.public_key:
            # Username already exists
            response = Response(self.SERVER_VERSION,
                                ResponseCodes.RECONNECT_REJECTED,
                                b"Restart as new client_side")
            client_socket.sendall(response.to_bytes())
            return

        # Encrypt the AES key using the client_side's public key
        public_key = RSA.import_key(client.public_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(client.aes_key)
        combined_payload = client.id + encrypted_aes_key

        # Construct the response
        response = Response(self.SERVER_VERSION,
                            ResponseCodes.APPROVE_RECONNECT_SEND_AES,
                            combined_payload)
        client_socket.sendall(response.to_bytes())

    @BaseProtocol.register_request(RequestCodes.SEND_PUBLIC_KEY)
    def _handle_public_key(self, client_socket: socket.socket,
                           request: Request) -> None:
        """
        Handle a public key request from a client_side. We extract the public key
        from the request, we then generate an AES key, store both in the DB,
        encrypt the AES key with the client_side's public key and send it back to
        the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        # Assuming the payload is structured as username|public_key
        # Extracting the username and public key
        public_key_pem = request.payload[CLIENTS_NAME_SIZE:]

        # Generate an AES key for the client_side
        aes_key = get_random_bytes(CLIENTS_AES_KEY_SIZE)  # AES-128 key

        # Update public key and AES key in the database
        self.db_handler.update_public_key_and_aes_key(
            client_id=request.client_id, aes_key=aes_key,
            public_key=public_key_pem)

        # Encrypt the AES key using the client_side's public key
        public_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        combined_payload = request.client_id + encrypted_aes_key

        # Construct the response
        response = Response(self.SERVER_VERSION,
                            ResponseCodes.RECEIVED_PUBLIC_KEY_SEND_AES,
                            combined_payload)
        client_socket.sendall(response.to_bytes())

    @BaseProtocol.register_request(RequestCodes.SEND_FILE)
    def _handle_file_transfer(self, client_socket: socket.socket,
                              request: Request) -> None:
        """
        Handle a file transfer request from a client_side. We extract the AES key
        associated with the client_side, then the file name and its encrypted
        contents. We then decrypt the file, store it locally and add it to
        our DB, perform a CRC and return the CRC to the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        # Retrieve the AES key for this client_side from the database
        aes_key = self.db_handler.get_aes_key_for_client(
            request.client_id)

        content_size = int.from_bytes(request.payload[0:4],
                                      byteorder='big')

        # Extract file name (trimming any null bytes)
        file_name = request.payload[4:259].decode('utf-8').rstrip('\0')

        # Extract the Base64 encoded encrypted content
        encrypted_content_hex = request.payload[
                                259:259 + content_size]

        # Decrypt using our AES CBC decryption method
        decrypted_file = decrypt_aes_cbc(encrypted_content_hex, aes_key)

        # Create the file (both locally "in storage") & in the DB:
        file = File(id=request.client_id, file_name=file_name,
                    path_name=os.path.join(FILES_STORAGE_FOLDER,
                                           request.client_id.hex(),
                                           file_name), verified=False)
        FileHandler(filepath=file.path_name, logger=self.logger).write_value(
            decrypted_file)
        # This will append the file to DB if user-file doesn't exist yet:
        self.db_handler.add_file(file=file)

        # Calculate the CRC checksum for the decrypted file
        crc_checksum = readfile_crc32(file.path_name, logger=self.logger)

        # ClientID - 16 bytes, Content Size - 4 bytes, File Name - 255
        # bytes, CRC Checksum - 4 bytes:
        response_payload = request.client_id
        response_payload += content_size.to_bytes(4, byteorder='big')
        response_payload += file_name.encode('utf-8').ljust(255, b'\0')
        response_payload += crc_checksum
        response = Response(self.SERVER_VERSION,
                            ResponseCodes.FILE_RECEIVED_CRC_OK,
                            response_payload)
        client_socket.sendall(response.to_bytes())

    @BaseProtocol.register_request(RequestCodes.CRC_CORRECT)
    def _handle_confirm_crc(self, client_socket: socket.socket,
                            request: Request) -> None:
        """
        Receives a client_side socket and a request, updates the file verified
        boolean field in the DB and sends a confirmation message to the
        client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        # Update verified field to True:
        file_name = request.payload[:255].decode('utf-8').rstrip('\0')
        self.db_handler.update_file_verified(client_id=request.client_id,
                                             file_name=file_name,
                                             verified=True)
        response = Response(self.SERVER_VERSION,
                            ResponseCodes.CONFIRM_MSG,
                            payload=request.client_id)
        client_socket.sendall(response.to_bytes())

    @BaseProtocol.register_request(RequestCodes.CRC_INCORRECT_RESEND)
    def _handle_bad_crc_resend(self, client_socket, request: Request) -> None:
        """
        Receives a client_side socket and a request and logs a warning message to
        indicate that we received an invalid CRC message once.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        file_name = request.payload[:255].decode('utf-8').rstrip('\0')
        self.logger.info(f"Accepted a CRC invalid resend message for the"
                         f"file: '{file_name}'")

    @BaseProtocol.register_request(RequestCodes.CRC_INCORRECT_DONE)
    def _handle_invalid_crc(self, client_socket: socket.socket,
                            request: Request) -> None:
        """
        Receives a client_side socket and a request and logs a warning message to
        indicate that we finished handling client_side with invalid crc status.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        file_name = request.payload[:255].decode('utf-8').rstrip('\0')
        self.logger.warning(f"Client file transfer of '{file_name}' failed.")

    @BaseProtocol.register_request(RequestCodes.INVALID_VERSION)
    def _handle_version_error(self, client_socket: socket.socket,
                              request: Request) -> None:
        """
        Receives a client_side socket and a request, logs an error message and
        sends it to the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        msg = f"Client version '{request.version}' != Server version " \
              f"'{SERVER_VERSION}'."
        self.logger.warning(msg)
        response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
                            msg.encode('utf-8'))
        client_socket.sendall(response.to_bytes())

    @BaseProtocol.register_request(RequestCodes.INVALID_CODE)
    def _handle_code_error(self, client_socket: socket.socket,
                           request: Request) -> None:
        """
        Receives a client_side socket and a request, logs an error message and
        sends it to the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        msg = f"Client request code '{request.code.value}' does not match " \
              f"any of the request codes implemented on the messages_server."
        self.logger.warning(msg)
        response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
                            msg.encode('utf-8'))
        client_socket.sendall(response.to_bytes())

    def handle_general_server_error(self, client_socket: socket.socket,
                                    request: Request) -> None:
        """
        Receives a client_side socket and a request, logs an error message and
        sends it to the client_side.
        @param client_socket: A socket we can pass messages through.
        @param request: The request parsed from the Client's message.
        """
        msg = f"A general messages_server error has occurred while attempting to " \
              f"handle request with code '{request.code.value}'. Please " \
              f"contact an administrator for further details."
        self.logger.warning(msg)
        response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
                            msg.encode('utf-8'))
        client_socket.sendall(response.to_bytes())
