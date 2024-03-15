"""
Author: Erez Drutin
Date: 02.11.2023
Purpose: The idea here is to simplify the work when registering new "route"
handlers for new request codes, such that whenever we add a new one, we can
simply wrap the method with its respective code, and we will automatically
get the logging and the handling "associated" with that code.
Note: This feels a bit like an overkill compared to the scope of the project,
thus I stopped here. Otherwise, I would have happily added another abstraction
layer to further distance the implementation level of the protocol handler
from the actual required methods using an "abstract" class as an interface.
"""
import logging
from socket import socket
from typing import Callable, Dict, Type, Any
from common.models import Request, Response
from common.consts import AuthRequestCodes, MessagesServerRequestCodes
from abc import ABC, abstractmethod

RequestCodesType = AuthRequestCodes | MessagesServerRequestCodes


class BaseProtocol(ABC):
    # A dictionary that will hold a mapping between request codes and
    # matching methods to trigger.
    request_handlers: Dict[RequestCodesType, Callable] = {}

    def __init__(self, version: int, logger=None):
        self.logger = logger if logger else logging.getLogger(
            self.__class__.__name__)
        self.version = version

    @abstractmethod
    def handle_incoming_message(self, client_socket: socket, **kwargs) -> Any:
        """ Handles incoming messages. """
        pass

    @classmethod
    def register_request(cls, code: RequestCodesType) -> Callable:
        """
        A class method to allow registration of request handler methods with
        specific request codes.
        @param code: A code to associate with the received method.
        @return: The received method.
        """

        def decorator(func):
            cls.request_handlers[code] = func
            return func

        return decorator

    def log_decorator(self, func: Callable):
        """
        A method to decorate by logging the request codes that we're handling.
        This is by design not a "requirement" as we may not always want our
        BaseProtocol implementers to log messages.
        @param func: A method to wrap.
        @return: The wrapped method.
        """

        def wrapper(client_socket: socket, request: Request, *args, **kwargs):
            info_msg = f"{request.code} from client ID: {request.client_id}"

            # Logging the request before receiving it and after handling it:
            self.logger.info(f"Received request code: {info_msg}")
            result: Response = func(self, client_socket, request, *args,
                                    **kwargs)

            self.logger.info(f"Finished handling request code: {info_msg}")

            return result

        return wrapper
