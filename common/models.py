"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: A file populated with models that will be used throughout the
entire code-base. Normally this would be separated into files and directories
based on functionality. However, in this case this seemed "excessive"
compared to the requirements as is.
"""
from _socket import inet_aton
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
from common.consts import AuthRequestCodes, MessagesServerRequestCodes, \
    AuthResponseCodes, MessagesServerResponseCodes


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
