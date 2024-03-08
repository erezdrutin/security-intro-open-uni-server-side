from __future__ import annotations
import logging
import socket
from typing import List, Any, Dict, Tuple, Optional
from client_side.auth_protocol_handler import AuthProtocolHandler
from client_side.consts import RequestCodeTypes, AuthRequestCodes, \
    MessagesServerRequestCodes, CLIENT_VERSION
from client_side.requests import RequestFactory
from common.consts import AuthResponseCodes, MessagesServerResponseCodes
from common.custom_exceptions import ServerDisconnectedError
from common.file_handler import FileHandler
from common.message_utils import unpack_server_message_headers
from common.models import Request


class Client:
    def __init__(self, server_port: int, server_ip: str, client_name: str,
                 client_id: bytes, protocol: AuthProtocolHandler,
                 client_password: str, logger: logging.Logger,
                 actions: List[RequestCodeTypes]):
        self.server_port = server_port
        self.server_ip = server_ip
        self.protocol: AuthProtocolHandler = protocol
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

    def _prepare_request(self, action: RequestCodeTypes) -> Dict[str, Any]:
        """ Prepares the kwargs dict based on the action to perform. """
        data = {}
        if action == AuthRequestCodes.GET_AES_KEY:
            data['server_id'] = self.server_id
        return data

    def _handle_request(self, action: RequestCodeTypes) -> Any:
        """
        Handles communication with a single server until we either receive
        an error, the server side disconnects or we finished our
        "connection" with the server.
        """
        # Perform a request using the client socket:
        kwargs = self._prepare_request(action=action)
        self.protocol.make_request(
            client_socket=self.client_socket,
            request=self.req_builder.create_request(action=action, **kwargs))
        # Determine whether current response belongs to Auth / Messages Server:
        res_type = AuthResponseCodes if isinstance(action, AuthRequestCodes) \
            else MessagesServerResponseCodes
        # handle incoming response:
        return self.protocol.handle_incoming_message(self.client_socket,
                                                     codes_type=res_type)

    def _parse_incoming_messages(self, action: RequestCodeTypes,
                                 request: Request) -> None:
        if action == AuthRequestCodes.CLIENT_REGISTRATION and \
                not self.client_id:
            # Update client id for all relevant dependencies:
            self.client_id = request.payload
            self.req_builder.client_id = request.payload
            # self.protocol.client_id = request.payload
        elif action == AuthRequestCodes.SERVER_REGISTRATION:
            self.server_id = request.payload

    def start(self) -> None:
        """
        Starts the client side based on the received parameters. Will send
        the initially received request to the server and manage the ongoing
        flow of request-responses communication with the server.
        """
        # Initialize a new socket and connect to it:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_ip, self.server_port))
        try:
            for action in self.actions:
                self._parse_incoming_messages(
                    action=action, request=self._handle_request(action=action))
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
    def init_logger(logger_name: str = "main", log_path: str = "logs.log") \
            -> logging.Logger:
        """
        A static method to initialize a logger, so we can use it throughout
        our messages_server code (or other code-parts in the future if relevant).
        This is a very basic implementation, in a real-world app the logger
        would be implemented with a FileRotator and a bit of a more
        "comprehensive" configuration.
        @param logger_name: A default name for the logger.
        @param log_path: A path to store inside logs from the app.
        @return: A python logger.
        """
        logging.basicConfig(
            level=logging.INFO,
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
        Loads client details from a file or prompts the user if the file path is empty.
        Returns the client name and client_id (as bytes or None).
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
                raise
        else:
            # Prompt for client name since me_path is empty
            client_name = input("Enter client name: ")
            client_password = input("Enter client password: ")
            return client_name, None, client_password

    @staticmethod
    def initialize_client(actions: List[RequestCodeTypes],
                          auth_server_path: str, me_path: str = '') -> Client:
        """
        Returns a Server instance. In general, a lot of the data here could
        be further simplified into "injection" via main (for example,
        rather than passing paths and consts, we can pass DBHandler,
        ProtocolHandler, ...), but this feels out of scope for this project.
        @param actions: A list of actions to perform via the client. Assumes
        the list is sequential in the sense that these actions will take
        place one right after the other.
        @param me_path: An (optional) path to a file in which we store
        details about the client_side.
        @param auth_server_path: A path to the file in which we store details
        about the Authentication server.
        @return: A messages_server instance.
        """
        logger = Client.init_logger()
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

        protocol = AuthProtocolHandler(logger=logger,
                                       client_id=client_id_bytes,
                                       client_key=password,
                                       client_name=name)

        return Client(server_port=int(port), server_ip=server_ip,
                      protocol=protocol, client_password=password,
                      logger=logger, client_name=name,
                      client_id=client_id_bytes, actions=actions)
