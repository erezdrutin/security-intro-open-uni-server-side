from socket import socket
from struct import calcsize, unpack
from typing import Tuple, Type, Callable, Dict, Any, TypeVar
from common.custom_exceptions import ClientDisconnectedError

# Creating a type variable that is bound to any class that can be instantiated
from common.models import Request

T = TypeVar('T')


def unpack_server_message_headers(client: socket) -> Tuple[int, int, int]:
    """
    Receives a client to take in messages with and returns a version, code
    and payload_size extracted from the message.
    The format string for struct.unpack:
    - B: version is a 1-byte unsigned char
    - H: code is a 2-byte unsigned short
    - I: payload_size is a 4-byte unsigned int
    Assuming the total size of the struct is:
    (1 + 2 + 4 = 7 bytes) without the payload.
    @param client: A client to take in messages from
    @return: A tuple that consists of version, code, payload_size
    """
    format_string = ">BHI"
    size_without_payload = calcsize(format_string)
    data = client.recv(size_without_payload)

    # The client_side has disconnected, raise an error
    if data == b'':
        raise ClientDisconnectedError("Client has disconnected.")

    # Unpack the data
    version, code, payload_size = unpack(format_string, data)
    # Save client_id as bytes and remove trailing null bytes
    return version, code, payload_size


def unpack_client_message_headers(client: socket) \
        -> Tuple[bytes, int, int, int]:
    """
    Receives a client to take in messages with and returns a client_id,
    version, code and payload_size extracted from the message.
    The format string for struct.unpack:
    - 16s: client_id is a 16-byte string
    - B: version is a 1-byte unsigned char
    - H: code is a 2-byte unsigned short
    - I: payload_size is a 4-byte unsigned int
    Assuming the total size of the struct is:
    (16 + 1 + 2 + 4 = 23 bytes) without the payload.
    @param client: A client to take in messages from
    @return: A tuple that consists of client_id, version, code, payload_size
    """
    format_string = ">16sBHI"
    size_without_payload = calcsize(format_string)
    data = client.recv(size_without_payload)

    # The client_side has disconnected, raise an error
    if data == b'':
        raise ClientDisconnectedError("Client has disconnected.")

    # Unpack the data
    client_id_bytes, version, code, payload_size = unpack(
        format_string, data)
    # Save client_id as bytes and remove trailing null bytes
    client_id = client_id_bytes.replace(b'\x00', b'')
    return client_id, version, code, payload_size


def unpack_message(
        client: socket, client_id: bytes, version: int, code: int,
        payload_size: int, accepted_version: int, codes: Type[T],
        request_handlers: Dict[Any, Callable]) -> Tuple[Request, Callable]:
    """
    A method that validates the contents of a received message and attempts
    to find a matching handler for it based on the provided parameters.
    @param client: A client socket from which we expect to receive messages.
    @param client_id: An id associated with the client being handled.
    @param version: A version associated with the client request.
    @param code: A code for the client's request.
    @param payload_size: The size of the message sent by the client.
    @param accepted_version: The actual version we accept.
    @param codes: A dataclass to load requests with.
    @param request_handlers: A dict of request Codes and matching callable
    methods to handle their respective codes.
    @return: A request instance and a callable (handler) method.
    """
    try:
        code = codes(code)
    except ValueError:
        code = codes.INVALID_CODE

    # Read the payload based on the payload_size
    payload = client.recv(payload_size)

    request = Request(client_id, version, code,
                      payload, payload_size)

    # Trigger handler based on request code + wrap with logger:
    if version != accepted_version:
        handler = request_handlers[codes.INVALID_VERSION]
    elif request.code not in request_handlers:
        handler = request_handlers[codes.INVALID_CODE]
    else:
        handler = request_handlers[request.code]
    return request, handler
