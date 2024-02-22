from __future__ import annotations
import logging
import socket
import struct

from common.file_handler import FileHandler
from common.models import Request


class Client:
    def __init__(self, server_ip: str, server_port: int, client_name: str,
                 client_id: bytes, logger: logging.Logger):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_name = client_name
        self.client_id = client_id
        self.logger = logger

    def send_request(self, request: Request) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.server_ip, self.server_port))
            sock.sendall(request.to_bytes())
            self.logger.info("Request sent successfully.")
            response = sock.recv(1024)
            self.logger.info(f"Response received: {response}")

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
    def initialize_client(me_path: str, auth_server_path: str) -> Client:
        """
        Returns a Server instance. In general, a lot of the data here could
        be further simplified into "injection" via main (for example,
        rather than passing paths and consts, we can pass DBHandler,
        ProtocolHandler, ...), but this feels out of scope for this project.
        @param me_path: A path to the file in which we store details about
        the client_side.
        @param auth_server_path: A path to the file in which we store details
        about the Authentication server.
        @return: A messages_server instance.
        """
        logger = Client.init_logger()
        try:
            client_details_loader = FileHandler(me_path, logger=logger)
            auth_server_loader = FileHandler(auth_server_path, logger=logger)
            server_ip, port = auth_server_loader.load_value().split(':')
            name, client_id = client_details_loader.load_value().split('\n')
        except (ValueError, AttributeError, IndexError, Exception) as err:
            logging.error('Unable to load client_side configuration. Please '
                          'validate both me.info and srv.info files.')
            raise err
        # Return the initialized messages_server:
        return Client(server_ip=server_ip, server_port=int(port),
                      client_name=name, client_id=client_id.encode('utf-8'),
                      logger=logger)
