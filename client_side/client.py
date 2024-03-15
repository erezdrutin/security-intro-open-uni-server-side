"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Define the overall structure of a client.
"""
from __future__ import annotations
import logging
import socket
from typing import List, Any, Dict, Tuple, Optional
from client_side.protocol_handler import ProtocolHandler
from client_side.consts import RequestCodeTypes, AuthRequestCodes, \
    MessagesServerRequestCodes, CLIENT_VERSION
from client_side.requests import RequestFactory
from common.consts import AuthResponseCodes, MessagesServerResponseCodes
from common.custom_exceptions import ServerDisconnectedError
from common.file_handler import FileHandler
from common.models import Request, Server, ClientMessage


class Client:
    def __init__(self, server_port: int, server_ip: str, client_name: str,
                 client_id: bytes, protocol: ProtocolHandler,
                 client_password: str, logger: logging.Logger,
                 actions: List[RequestCodeTypes]):
        """
        Initializes the client with the server connection details,
        authentication information, and logger.
        @param server_port: The port number of the server to connect to.
        @param server_ip: The IP address of the server to connect to.
        @param client_name: The name of the client.
        @param client_id: A unique identifier for the client, in bytes.
        @param protocol: A ProtocolHandler instance.
        @param client_password: The password of the client for authentication.
        @param logger: A logging.Logger instance for logging messages.
        @param actions: A list of RequestCodeTypes detailing the actions the
        client intends to perform.
        """
        self.server_port = server_port
        self.server_ip = server_ip
        self.protocol: ProtocolHandler = protocol
        self.logger = logger
        self.client_id = client_id
        self.client_name = client_name
        self.client_password = client_password
        self.client_socket = None
        self.server_id = None
        self.actions = actions
        self.req_builder = RequestFactory(
            version=CLIENT_VERSION, logger=self.logger,
            client_id=self.client_id, client_name=self.client_name,
            client_password=self.client_password)

    def _prepare_request(self, action: RequestCodeTypes,
                         request: Optional[Request]) -> Dict[str, Any]:
        """
        Prepares the request dictionary to be sent based on the action.
        @param action: an action to be performed, based on the RequestCodeType.
        @param request: An optional Request to include during request prep.
        @return: A dictionary with the prepared request data.
        """
        data = {}
        if action == AuthRequestCodes.GET_AES_KEY:
            data['server_id'] = self.server_id
            data['nonce'] = self.protocol.nonce
        elif action == MessagesServerRequestCodes.AUTHENTICATE:
            # Close AUTH SERVER client connection:
            self.client_socket.close()
            # Open a new client connection to MSG SERVER:
            self.client_socket = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)
            # Assuming these were previously updated at the SERVERS_LIST step:
            self.client_socket.connect((self.server_ip, self.server_port))
            data['payload'] = request.payload
        elif action == MessagesServerRequestCodes.SEND_MESSAGE:
            # Assuming the client is already connected to the correct socket.
            msg = ClientMessage.create(aes_key=self.protocol.shared_aes_key)
            # decrypted_msg = EncryptedMessage.from_bytes(
            #     msg.to_bytes(), aes_key=self.protocol.shared_aes_key)
            # print(decrypted_msg)
            data['payload'] = msg.to_bytes()

        return data

    def _handle_request(self, action: RequestCodeTypes,
                        last_request: Optional[Request]) -> Any:
        """
        Handles the process of sending a request to the server and receiving
        a response.
        @param action: The action to be performed based on the RequestCodeType.
        @param last_request: The last request sent to the server, used for
        context (if necessary).
        @return: The response from the server.
        """
        # Perform a request using the client socket:
        kwargs = self._prepare_request(action=action, request=last_request)
        self.protocol.make_request(
            client_socket=self.client_socket,
            request=self.req_builder.create_request(action=action, **kwargs))

        # Determine whether current response belongs to Auth / Messages Server:
        res_type = AuthResponseCodes if isinstance(action, AuthRequestCodes) \
            else MessagesServerResponseCodes

        # handle incoming response:
        return self.protocol.handle_incoming_message(self.client_socket,
                                                     codes_type=res_type)

    def _parse_incoming_requests_results(self, action: RequestCodeTypes,
                                         request: Request) -> None:
        """
        Parses the results of incoming requests based on the action performed.
        @param action: The requested action, based on the RequestCodeType.
        @param request: The request object that was sent to the server.
        """
        if action == AuthRequestCodes.CLIENT_REGISTRATION and \
                not self.client_id:
            # Update client id for all relevant dependencies:
            self.client_id = request.payload
            self.req_builder.client_id = request.payload
            # self.protocol.client_id = request.payload
        elif action == AuthRequestCodes.SERVER_REGISTRATION:
            self.server_id = request.payload
        elif action == AuthRequestCodes.SERVERS_LIST:
            server = Server.from_bytes(request.payload, version=CLIENT_VERSION)
            self.server_ip = server.ip
            self.server_port = server.port
            self.server_id = server.id

    def start(self) -> None:
        """
        Initiates the client's action sequence, managing the connection to
        the server and handling request-response flows.
        """
        # Initialize a new socket and connect to it:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_ip, self.server_port))
        try:
            last_request = None
            for action in self.actions:
                last_request = self._handle_request(
                    action=action, last_request=last_request)
                self._parse_incoming_requests_results(action=action,
                                                      request=last_request)
        except (ConnectionResetError, BrokenPipeError,
                ServerDisconnectedError) as err:
            # Server disconnected unexpectedly
            self.logger.warning(f"Server disconnected unexpectedly: {err}")
        except Exception as e:
            # Handle or log other exceptions
            self.logger.error(f"Error while handling server connection: {e}")
        finally:
            # Close the socket from client side:
            self.client_socket.close()
            self.logger.warning(f"Connection closed.")

    @staticmethod
    def init_logger(logger_name: str = "main", log_path: str = "logs.log",
                    logger_level: int = logging.INFO) \
            -> logging.Logger:
        """
        Initializes and returns a logger instance for logging messages.
        @param logger_name: The name for the logger instance.
        @param log_path: The file path where the log messages will be stored.
        @param logger_level: The logging level for the logger instance.
        @return: A configured logging.Logger instance.
        """
        logging.basicConfig(
            level=logger_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ])
        return logging.getLogger(logger_name)

    @staticmethod
    def fetch_client_details(me_path: str, logger: logging.Logger) \
            -> Tuple[str, Optional[bytes], str]:
        """
        Fetches client details from a specified file path or prompts the user
        for input if the file path is empty.
        @param me_path: The file path to load client details from.
        @param logger: A logging.Logger instance for logging messages.
        @return: A tuple containing the client name, client_id (/None) and
        client password.
        """
        if me_path:
            try:
                client_details_loader = FileHandler(me_path, logger=logger)
                name, _id, password = client_details_loader.load_value().split(
                    '\n')
                client_id_bytes = _id.encode('utf-8')
                return name, client_id_bytes, password
            except (ValueError, AttributeError, IndexError, Exception) as err:
                logger.error(
                    'Unable to load client_side configuration from me_path. '
                    f'Error: {err}')
        # Prompt for client name since me_path is empty
        client_name = input("Enter client name: ")
        client_password = input("Enter client password: ")
        return client_name, None, client_password

    @staticmethod
    def initialize_client(actions: List[RequestCodeTypes],
                          auth_server_path: str, me_path: str = '') -> Client:
        """
        Initializes and returns a client instance with the specified config.
        @param actions: A list of actions the client will perform.
        @param me_path: An optional file path for storing client details.
        @param auth_server_path: The file path containing authentication
        server details.
        @return: An initialized Client instance.
        """
        logger = Client.init_logger(logger_level=logging.DEBUG)
        try:
            auth_server_loader = FileHandler(auth_server_path, logger=logger)
            server_ip, port = auth_server_loader.load_value().split(':')
            name, client_id_bytes, password = Client.fetch_client_details(
                me_path=me_path, logger=logger)
        except (ValueError, AttributeError, IndexError, Exception) as err:
            logger.error(
                'Unable to initialize client. Please validate the auth '
                f'server configuration. Error: {err}')
            raise err

        protocol = ProtocolHandler(logger=logger,
                                   client_id=client_id_bytes,
                                   client_key=password,
                                   client_name=name)

        return Client(server_port=int(port), server_ip=server_ip,
                      protocol=protocol, client_password=password,
                      logger=logger, client_name=name,
                      client_id=client_id_bytes, actions=actions)
