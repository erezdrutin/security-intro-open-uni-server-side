"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: A file populated with models that will be used throughout the
entire code-base. Normally this would be separated into files and directories
based on functionality. However, in this case this seemed "excessive"
compared to the requirements as is.
"""

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
    port: str


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
        client_id_bytes = self.client_id[:16].ljust(16, b'\x00')
        version_bytes = self.version.to_bytes(1, byteorder='big')
        code_bytes = self.code.value.to_bytes(2, byteorder='big')
        payload_size_bytes = self.payload_size.to_bytes(4, byteorder='big')
        payload_bytes = self.payload

        # Concatenate all parts in the specified order
        return client_id_bytes + version_bytes + code_bytes + payload_size_bytes + payload_bytes


@dataclass
class Response:
    version: str
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
        version_bytes = self.version.encode('utf-8')
        code_bytes = self.code.value.to_bytes(2, byteorder='big')
        payload_size_bytes = self.payload_size.to_bytes(4, byteorder='big')
        return version_bytes + code_bytes + payload_size_bytes + self.payload
