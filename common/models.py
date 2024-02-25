"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: A file populated with models that will be used throughout the
entire code-base. Normally this would be separated into files and directories
based on functionality. However, in this case this seemed "excessive"
compared to the requirements as is.
"""
from __future__ import annotations
from _socket import inet_aton
from base64 import b64encode, b64decode
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
from common.consts import AuthRequestCodes, MessagesServerRequestCodes, \
    AuthResponseCodes, MessagesServerResponseCodes
from common.aes_cipher import AESCipher
from common.utils import dt_with_ttl_to_ts, convert_bytes_to_timestamp


@dataclass
class Client:
    id: bytes
    name: str
    password_hash: bytes
    last_seen: datetime


@dataclass
class Server:
    id: bytes
    name: str
    ip: str
    port: int
    version: int
    aes_key: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """ Returns a byte sequence representation for the Server dataclass.
        The byte sequence representation DOES NOT INCLUDE AES KEY."""
        # Ensure server ID is exactly 16 bytes and server name is 255 bytes:
        id_bytes = self.id[:16].ljust(16, b'\x00')
        name_bytes = self.name.encode('utf-8')[:255].ljust(255, b'\x00')

        # Convert IP address to 4 bytes and port to 2 bytes:
        ip_bytes = inet_aton(self.ip)
        port_bytes = self.port.to_bytes(2, byteorder='big')

        # Concatenate all parts in the specified order
        return id_bytes + name_bytes + ip_bytes + port_bytes


@dataclass
class ServerState:
    clients: List[Client]
    servers: List[Server]


@dataclass
class Request:
    client_id: bytes
    version: int
    code: AuthRequestCodes | MessagesServerRequestCodes
    payload: bytes
    _payload_size: Optional[int] = None

    @property
    def payload_size(self) -> int:
        return self._payload_size or len(self.payload)

    def to_bytes(self) -> bytes:
        """
        Converts the request details dataclass into a byte sequence.
        """
        # Ensure client_id is exactly 16 bytes (with padding / truncate)
        client_id_bytes = (b'' if self.client_id is None else
                           self.client_id[:16]).ljust(16, b'\x00')
        version_bytes = self.version.to_bytes(1, byteorder='big')
        code_bytes = self.code.value.to_bytes(2, byteorder='big')
        payload_size_bytes = self.payload_size.to_bytes(4, byteorder='big')
        payload_bytes = self.payload

        # Concatenate all parts in the specified order
        return client_id_bytes + version_bytes + code_bytes + payload_size_bytes + payload_bytes


@dataclass
class Response:
    version: int
    code: AuthResponseCodes | MessagesServerResponseCodes
    payload: bytes

    @property
    def payload_size(self):
        return len(self.payload)

    def to_bytes(self) -> bytes:
        """
        Converts the response details dataclass into a byte sequence which
        will in turn be sent to the Client.
        @return: A bytes sequence.
        """
        version_bytes = self.version.to_bytes(1, byteorder='big')
        code_bytes = self.code.value.to_bytes(2, byteorder='big')
        payload_size_bytes = self.payload_size.to_bytes(4, byteorder='big')
        return version_bytes + code_bytes + payload_size_bytes + self.payload


@dataclass
class EncryptedKey:
    shared_iv: bytes
    encrypted_nonce: bytes
    client_encrypted_aes: bytes

    def to_bytes(self) -> bytes:
        # Encrypted key = 16 bytes (IV) + ENCRYPTED 8 bytes (Nonce) +
        # ENCRYPTED 32 bytes (AES):
        return self.shared_iv + self.encrypted_nonce \
               + self.client_encrypted_aes

    @staticmethod
    def from_bytes(encrypted_key: bytes, cipher: AESCipher) -> EncryptedKey:
        """
        Both encrypted_nonce and encrypted_aes will be in b64decoded format.
        @param encrypted_key: A byte sequence representing an encrypted key.
        @param cipher: A cipher to encrypt the key with.
        @return: An instance of this dataclass.
        """
        shared_iv = encrypted_key[:16]
        encrypted_nonce = encrypted_key[16:32]
        encrypted_aes = encrypted_key[32:]
        # Decrypt the encrypted values:
        nonce = cipher.decrypt(encrypted_nonce)
        shared_aes_key = cipher.decrypt(encrypted_aes)

        return EncryptedKey(shared_iv=shared_iv, encrypted_nonce=nonce,
                            client_encrypted_aes=shared_aes_key)

    @staticmethod
    def create(shared_iv: bytes, shared_aes_key: str, nonce: bytes,
               cipher: AESCipher):
        encrypted_nonce = cipher.encrypt(nonce)
        client_encrypted_aes = cipher.encrypt(shared_aes_key.encode('utf-8'))
        return EncryptedKey(shared_iv=shared_iv,
                            encrypted_nonce=encrypted_nonce,
                            client_encrypted_aes=client_encrypted_aes)


@dataclass
class BaseTicket:
    version: int
    client_id: bytes
    server_id: bytes
    creation_time: datetime
    ticket_iv: bytes


@dataclass
class DecryptedTicket(BaseTicket):
    decrypted_aes_key: str
    decrypted_expiration_time: datetime

    @staticmethod
    def from_bytes(data: bytes, cipher: AESCipher) -> DecryptedTicket:
        # Load an instance of Ticket from bytes representation.
        version = data[0]
        client_id = data[1:17]
        server_id = data[17:33]
        creation_time = datetime.fromtimestamp(
            int.from_bytes(data[33:41], byteorder='big'))
        ticket_iv = data[41:57]
        # b64 decoded aes is 48 bytes:
        encrypted_aes_key = data[57:57 + 64]
        # encrypted_expiration_time is 16 bytes, from the end
        encrypted_expiration_time = data[len(data) - 16:]

        aes_key = b64encode(cipher.decrypt(encrypted_aes_key)).decode('utf-8')
        expiration_time = convert_bytes_to_timestamp(cipher.decrypt(
            encrypted_expiration_time))

        return DecryptedTicket(version=version, client_id=client_id,
                               server_id=server_id,
                               creation_time=creation_time,
                               ticket_iv=ticket_iv,
                               decrypted_aes_key=aes_key,
                               decrypted_expiration_time=expiration_time)


@dataclass
class EncryptedTicket(BaseTicket):
    encrypted_aes_key: bytes
    encrypted_expiration_time: bytes

    def to_bytes(self) -> bytes:
        # Convert the Ticket instance into bytes representation.
        version_bytes = self.version.to_bytes(1, byteorder='big')
        client_id_bytes = self.client_id.ljust(16, b'\x00')
        server_id_bytes = self.server_id.ljust(16, b'\x00')
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(
            8, byteorder='big')

        return version_bytes + client_id_bytes + server_id_bytes + \
               creation_time_bytes + self.ticket_iv + \
               self.encrypted_aes_key + self.encrypted_expiration_time

    @staticmethod
    def create(version: int, client_id: bytes, server_id: bytes,
               creation_time: datetime, shared_iv: bytes, aes_key: str,
               ticket_ttl_sec: int, cipher: AESCipher) -> EncryptedTicket:
        # Padded to 64 bytes after encryption:
        server_encrypted_aes = cipher.encrypt(b64decode(aes_key))
        expiration_ts = dt_with_ttl_to_ts(creation_time, ticket_ttl_sec)
        # Padded to 16 bytes after encryption:
        encrypted_expiration = cipher.encrypt(
            expiration_ts.to_bytes(8, byteorder='big'))
        # Create and return the Ticket instance
        return EncryptedTicket(
            version=version,
            client_id=client_id,
            server_id=server_id,
            creation_time=creation_time,
            ticket_iv=shared_iv,
            encrypted_aes_key=server_encrypted_aes,
            encrypted_expiration_time=encrypted_expiration
        )
