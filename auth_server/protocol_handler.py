import logging
import socket
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from typing import Any
from hashlib import sha256
from uuid import uuid4
from auth_server.consts import SERVER_VERSION, RequestCodes, ResponseCodes, \
    TICKET_TTL_SEC
from common.aes_cipher import AESCipher
from common.consts import AuthRequestCodes
from common.db_handler import DatabaseHandler
from common.models import Request, Response, Client, Server, EncryptedKey, \
    EncryptedTicket, DecryptedTicket, DecryptedKey
from common.base_protocol import BaseProtocol
from common.message_utils import unpack_client_message_headers, unpack_message
from common.utils import enforce_len, dt_with_ttl_to_ts


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
        # Extract name & password from the payload, apply sha256 on password:
        client_name = request.payload[:255].rstrip(b'\0').decode('utf-8')
        client_password = sha256(request.payload[255:510]).digest()
        print(f"CLIENT PASS SHA --> {client_password}")
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
        # Extract name & password from the payload, apply sha256 on password:
        server_name = request.payload[:255].rstrip(b'\0').decode('utf-8')
        aes_key = request.payload[255:287]
        server_ip = socket.inet_ntoa(request.payload[287:291])
        server_port = int.from_bytes(request.payload[291:293], "big")
        # Generate a 16 bit UUID for the client:
        server_id = uuid4().bytes
        # Register new server in DB
        db_res = self.db_handler.add_server(server=Server(
            id=server_id,
            name=server_name,
            ip=server_ip,
            port=server_port,
            aes_key=aes_key,
            version=request.version
        ))

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
        shared_iv = AESCipher.create_iv()
        shared_aes_key = AESCipher.create_aes_key()
        server_id = request.payload[:16]
        nonce = request.payload[16:24]

        # Encrypted key construction (with client key):
        client = self.db_handler.get_client_by_id(_id=request.client_id)
        cipher = AESCipher(client.password_hash.hex(), shared_iv)
        encrypted_key = EncryptedKey.create(
            shared_iv=shared_iv, shared_aes_key=shared_aes_key, nonce=nonce,
            cipher=cipher)

        encrypted_on_decrypt = DecryptedKey.from_bytes(
            encrypted_key.to_bytes(), client.password_hash.hex())

        print("––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––")
        print(f"KEY STUFF - IV: {shared_iv}, AES: {shared_aes_key}, "
              f"NONCE:{nonce}")
        # print(f"ENCRYPTED KEY TO BYTES: {encrypted_key.to_bytes()}")
        # print(f"LEN ENCRYPTED KEY IN BYTES: {len(encrypted_key.to_bytes())}")
        # cipher = AESCipher(client.password_hash.hex())
        # encrypted_nonce = cipher.encrypt(nonce)
        # client_encrypted_aes = cipher.encrypt(b64decode(shared_aes_key))
        # Encrypted key = 16 bytes (IV) + ENCRYPTED 8 bytes (Nonce) +
        # ENCRYPTED 32 bytes (AES):
        # encrypted_key = shared_iv + encrypted_nonce + client_encrypted_aes
        # encrypted_key = EncryptedKey.from_bytes(
        #     encrypted_key_new.to_bytes(), cipher)

        # self.logger.debug(f"encrypted key --> {encrypted_key}")
        # self.logger.debug(
        #     f"decrypted values:\nnonce: {cipher.decrypt(encrypted_nonce)}"
        #     f"\nnew_aes: {b64encode(cipher.decrypt(client_encrypted_aes))}")

        # encrypted_from_bytes = EncryptedKey.from_bytes(encrypted_key, cipher)

        # Ticket construction (with messages server key):
        server = self.db_handler.get_server_by_id(server_id=server_id)
        cipher = AESCipher(server.aes_key.hex())
        server_encrypted_aes = cipher.encrypt(b64decode(shared_aes_key))
        creation_time = datetime.now()
        expiration_ts = dt_with_ttl_to_ts(creation_time, TICKET_TTL_SEC)
        encrypted_expiration = cipher.encrypt(
            expiration_ts.to_bytes(8, byteorder='big'))

        ticket = EncryptedTicket.create(
            version=self.version, client_id=request.client_id,
            server_id=server.id, creation_time=creation_time,
            shared_iv=shared_iv, aes_key=shared_aes_key,
            ticket_ttl_sec=TICKET_TTL_SEC, cipher=cipher)

        print("––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––")
        print(f"TICKET STUFF:\nVERSION: {ticket.version}\n"
              f"CLIENT_ID: {ticket.client_id}\nSERVER_ID: {ticket.server_id}\n"
              f"CREATION_TIME: {ticket.creation_time}\nSHARED_IV: "
              f"{ticket.ticket_iv}\nAES_KEY: {shared_aes_key}\n"
              f"TICKET_TTL: {TICKET_TTL_SEC}")
        print("TICKET TO BYTES: ", ticket.to_bytes())

        # Ticket:
        # 1 byte ~ Version
        # 16 bytes ~ Client ID
        # 16 Bytes ~ Server ID
        # 8 Bytes ~ Creation Time
        # 16 Bytes ~ Ticket IV (==shared IV)
        # 32 Bytes ~ AES Key (==shared key), encrypted with server AES(!)
        # 8 bytes ~ Expiration Time, encrypted with server AES(!)
        ticket_2 = \
            server.version.to_bytes(1, byteorder='big') + \
            request.client_id[:16].ljust(16, b'\x00') + \
            server.id[:16].ljust(16, b'\x00') + \
            int(creation_time.timestamp()).to_bytes(8, byteorder='big') + \
            shared_iv + \
            server_encrypted_aes + \
            encrypted_expiration

        print(ticket_2)
        print(ticket.to_bytes() == ticket_2)
        decrypted_ticket = DecryptedTicket.from_bytes(ticket_2, cipher)
        self.logger.debug(f"ticket --> {ticket}")
        self.logger.debug(
            f"decrypted values:\naes: {cipher.decrypt(server_encrypted_aes)}"
            f"\nexpiration_timestamp: {cipher.decrypt(encrypted_expiration)}")

        payload = request.client_id + encrypted_key.to_bytes() + ticket.to_bytes()
        response = Response(
            version=self.version, code=ResponseCodes.AES_KEY,
            payload=payload)
        # Respond to the client:
        bytes_res = response.to_bytes()
        client_socket.sendall(bytes_res)

    # @BaseProtocol.register_request(RequestCodes.REGISTRATION)
    # def _handle_registration(self, client_socket: socket.socket,
    #                          request: Request) -> None:
    #     """
    #     Handles a registration request from a client_side. We first check if the
    #     client_side already exists in the DB, in which case we will send a
    #     REGISTRATION_FAILED response. Otherwise, creating the new client_side
    #     record in the DB and returns generated 16 bit clientId to the Client.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     # Extracting request details
    #     client_name = request.payload.decode('utf-8').strip('\x00').strip()
    #
    #     client_side = self.db_handler.get_client(client_name=client_name)
    #     if client_side:
    #         # client_side already exists
    #         response = Response(self.SERVER_VERSION,
    #                             ResponseCodes.REGISTRATION_FAILED, b"")
    #         client_socket.sendall(response.to_bytes())
    #         return
    #
    #     # Generating a 16 bit UUID for the client_side:
    #     client_id = uuid.uuid4().bytes
    #     client_side = Client(id=client_id, name=client_name, public_key=b'',
    #                     last_seen=datetime.now(), aes_key=b'')
    #
    #     # Add the client_side to the DB (with partial info):
    #     self.db_handler.add_client(client_side=client_side)
    #
    #     # Craft the response payload with the UUID
    #     response = Response(self.SERVER_VERSION,
    #                         ResponseCodes.REGISTRATION_SUCCESS, client_id)
    #     bytes_res = response.to_bytes()
    #     client_socket.sendall(bytes_res)
    #
    # @BaseProtocol.register_request(RequestCodes.RECONNECT)
    # def _handle_reconnect(self, client_socket: socket.socket,
    #                       request: Request) -> None:
    #     """
    #     Handle a reconnection request from a client_side. We first check if the
    #     client_side doesn't exist yet or if it doesn't have a public key
    #     generated, in which case we will return a RECONNECT_REJECTED
    #     response. Otherwise, encrypting, saving in the DB and sending the AES
    #     key to the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     # Extracting request details
    #     client_name = request.payload.decode('utf-8').strip('\x00').strip()
    #
    #     # Extract client_side details and update last seen in DB:
    #     client_side = self.db_handler.get_client(client_name=client_name)
    #     self.db_handler.update_client_last_seen(client_id=client_side.id)
    #     if not client_side or not client_side.public_key:
    #         # Username already exists
    #         response = Response(self.SERVER_VERSION,
    #                             ResponseCodes.RECONNECT_REJECTED,
    #                             b"Restart as new client_side")
    #         client_socket.sendall(response.to_bytes())
    #         return
    #
    #     # Encrypt the AES key using the client_side's public key
    #     public_key = RSA.import_key(client_side.public_key)
    #     cipher_rsa = PKCS1_OAEP.new(public_key)
    #     encrypted_aes_key = cipher_rsa.encrypt(client_side.aes_key)
    #     combined_payload = client_side.id + encrypted_aes_key
    #
    #     # Construct the response
    #     response = Response(self.SERVER_VERSION,
    #                         ResponseCodes.APPROVE_RECONNECT_SEND_AES,
    #                         combined_payload)
    #     client_socket.sendall(response.to_bytes())
    #
    # @BaseProtocol.register_request(RequestCodes.SEND_PUBLIC_KEY)
    # def _handle_public_key(self, client_socket: socket.socket,
    #                        request: Request) -> None:
    #     """
    #     Handle a public key request from a client_side. We extract the public key
    #     from the request, we then generate an AES key, store both in the DB,
    #     encrypt the AES key with the client_side's public key and send it back to
    #     the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     # Assuming the payload is structured as username|public_key
    #     # Extracting the username and public key
    #     public_key_pem = request.payload[CLIENTS_NAME_SIZE:]
    #
    #     # Generate an AES key for the client_side
    #     aes_key = get_random_bytes(CLIENTS_AES_KEY_SIZE)  # AES-128 key
    #
    #     # Update public key and AES key in the database
    #     self.db_handler.update_public_key_and_aes_key(
    #         client_id=request.client_id, aes_key=aes_key,
    #         public_key=public_key_pem)
    #
    #     # Encrypt the AES key using the client_side's public key
    #     public_key = RSA.import_key(public_key_pem)
    #     cipher_rsa = PKCS1_OAEP.new(public_key)
    #     encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    #     combined_payload = request.client_id + encrypted_aes_key
    #
    #     # Construct the response
    #     response = Response(self.SERVER_VERSION,
    #                         ResponseCodes.RECEIVED_PUBLIC_KEY_SEND_AES,
    #                         combined_payload)
    #     client_socket.sendall(response.to_bytes())
    #
    # @BaseProtocol.register_request(RequestCodes.SEND_FILE)
    # def _handle_file_transfer(self, client_socket: socket.socket,
    #                           request: Request) -> None:
    #     """
    #     Handle a file transfer request from a client_side. We extract the AES key
    #     associated with the client_side, then the file name and its encrypted
    #     contents. We then decrypt the file, store it locally and add it to
    #     our DB, perform a CRC and return the CRC to the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     # Retrieve the AES key for this client_side from the database
    #     aes_key = self.db_handler.get_aes_key_for_client(
    #         request.client_id)
    #
    #     content_size = int.from_bytes(request.payload[0:4],
    #                                   byteorder='big')
    #
    #     # Extract file name (trimming any null bytes)
    #     file_name = request.payload[4:259].decode('utf-8').rstrip('\0')
    #
    #     # Extract the Base64 encoded encrypted content
    #     encrypted_content_hex = request.payload[
    #                             259:259 + content_size]
    #
    #     # Decrypt using our AES CBC decryption method
    #     decrypted_file = decrypt_aes_cbc(encrypted_content_hex, aes_key)
    #
    #     # Create the file (both locally "in storage") & in the DB:
    #     file = File(id=request.client_id, file_name=file_name,
    #                 path_name=os.path.join(FILES_STORAGE_FOLDER,
    #                                        request.client_id.hex(),
    #                                        file_name), verified=False)
    #     FileHandler(filepath=file.path_name, logger=self.logger).write_value(
    #         decrypted_file)
    #     # This will append the file to DB if user-file doesn't exist yet:
    #     self.db_handler.add_file(file=file)
    #
    #     # Calculate the CRC checksum for the decrypted file
    #     crc_checksum = readfile_crc32(file.path_name, logger=self.logger)
    #
    #     # ClientID - 16 bytes, Content Size - 4 bytes, File Name - 255
    #     # bytes, CRC Checksum - 4 bytes:
    #     response_payload = request.client_id
    #     response_payload += content_size.to_bytes(4, byteorder='big')
    #     response_payload += file_name.encode('utf-8').ljust(255, b'\0')
    #     response_payload += crc_checksum
    #     response = Response(self.SERVER_VERSION,
    #                         ResponseCodes.FILE_RECEIVED_CRC_OK,
    #                         response_payload)
    #     client_socket.sendall(response.to_bytes())
    #
    # @BaseProtocol.register_request(RequestCodes.CRC_CORRECT)
    # def _handle_confirm_crc(self, client_socket: socket.socket,
    #                         request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request, updates the file verified
    #     boolean field in the DB and sends a confirmation message to the
    #     client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     # Update verified field to True:
    #     file_name = request.payload[:255].decode('utf-8').rstrip('\0')
    #     self.db_handler.update_file_verified(client_id=request.client_id,
    #                                          file_name=file_name,
    #                                          verified=True)
    #     response = Response(self.SERVER_VERSION,
    #                         ResponseCodes.CONFIRM_MSG,
    #                         payload=request.client_id)
    #     client_socket.sendall(response.to_bytes())
    #
    # @BaseProtocol.register_request(RequestCodes.CRC_INCORRECT_RESEND)
    # def _handle_bad_crc_resend(self, client_socket, request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request and logs a warning message to
    #     indicate that we received an invalid CRC message once.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     file_name = request.payload[:255].decode('utf-8').rstrip('\0')
    #     self.logger.info(f"Accepted a CRC invalid resend message for the"
    #                      f"file: '{file_name}'")
    #
    # @BaseProtocol.register_request(RequestCodes.CRC_INCORRECT_DONE)
    # def _handle_invalid_crc(self, client_socket: socket.socket,
    #                         request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request and logs a warning message to
    #     indicate that we finished handling client_side with invalid crc status.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     file_name = request.payload[:255].decode('utf-8').rstrip('\0')
    #     self.logger.warning(f"Client file transfer of '{file_name}' failed.")
    #
    # @BaseProtocol.register_request(RequestCodes.INVALID_VERSION)
    # def _handle_version_error(self, client_socket: socket.socket,
    #                           request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request, logs an error message and
    #     sends it to the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     msg = f"Client version '{request.version}' != Server version " \
    #           f"'{SERVER_VERSION}'."
    #     self.logger.warning(msg)
    #     response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
    #                         msg.encode('utf-8'))
    #     client_socket.sendall(response.to_bytes())
    #
    # @BaseProtocol.register_request(RequestCodes.INVALID_CODE)
    # def _handle_code_error(self, client_socket: socket.socket,
    #                        request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request, logs an error message and
    #     sends it to the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     msg = f"Client request code '{request.code.value}' does not match " \
    #           f"any of the request codes implemented on the messages_server."
    #     self.logger.warning(msg)
    #     response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
    #                         msg.encode('utf-8'))
    #     client_socket.sendall(response.to_bytes())
    #
    # def handle_general_server_error(self, client_socket: socket.socket,
    #                                 request: Request) -> None:
    #     """
    #     Receives a client_side socket and a request, logs an error message and
    #     sends it to the client_side.
    #     @param client_socket: A socket we can pass messages through.
    #     @param request: The request parsed from the Client's message.
    #     """
    #     msg = f"A general messages_server error has occurred while attempting to " \
    #           f"handle request with code '{request.code.value}'. Please " \
    #           f"contact an administrator for further details."
    #     self.logger.warning(msg)
    #     response = Response(self.SERVER_VERSION, ResponseCodes.GENERAL_ERROR,
    #                         msg.encode('utf-8'))
    #     client_socket.sendall(response.to_bytes())
