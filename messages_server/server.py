from __future__ import annotations
import logging
import socket
import threading
from typing import Dict, Any

from common.consts import AuthRequestCodes
from common.models import Server as ServerModel
from const import DEFAULT_PORT
from common.custom_exceptions import ClientDisconnectedError
from common.file_handler import FileHandler
from common.db_handler import DatabaseHandler
from messages_server.protocol_handler import ProtocolHandler


class Server:
    def __init__(self, server: ServerModel, db_handler: DatabaseHandler,
                 protocol: ProtocolHandler, logger: logging.Logger):
        self.server = server
        self.db_handler = db_handler
        self.server_socket = None
        self.protocol: ProtocolHandler = protocol
        self.logger = logger

    def _handle_client(self, client_socket: socket.socket) -> None:
        """
        Handles communication with a single client_side until we either receive
        an error or the client_side disconnects.
        @param client_socket: A socket to read messages from.
        @return:
        """
        try:
            while True:
                # For each new message in the socket, trigger handle_request:
                self.protocol.handle_incoming_message(
                    client_socket=client_socket, codes_type=AuthRequestCodes)
        except ClientDisconnectedError as err:
            self.logger.warning(str(err))
        except (ConnectionResetError, BrokenPipeError):
            # Client disconnected unexpectedly
            self.logger.warning("Client disconnected unexpectedly.")
        except Exception as e:
            # Handle or log other exceptions
            self.logger.error(f"Error while handling client_side: {e}")
        finally:
            # Close the socket from messages_server-side:
            client_socket.close()
            self.logger.warning(f"Connection closed.")

    def start(self) -> None:
        """
        Starts the messages_server, allowing it to accept connections on self.port.
        The binding to 0.0.0.0 binds the messages_server to current hostname. The
        method sets up the messages_server socket and listens for incoming
        connections. For each new connection, it logs the event and starts a
        new thread for client_side handling. This is an endless method.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.server.port))
        # Queuing up to 5 requests at a time:
        self.server_socket.listen(5)
        self.logger.info(
            f"Messages server started on port {self.server.port}. Waiting for "
            f"connections...")

        while True:
            client_socket, addr = self.server_socket.accept()
            self.logger.warning(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self._handle_client,
                                             args=(client_socket,))
            client_thread.start()

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
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ])
        return logging.getLogger(logger_name)

    @staticmethod
    def initialize_server(
            db_config: Dict[str, Dict[str, Any]], db_file: str,
            server_id: bytes, servers_tbl: str) -> Server:
        """
        Returns a Server instance. In general, a lot of the data here could
        be further simplified into "injection" via main (for example,
        rather than passing paths and consts, we can pass DBHandler,
        ProtocolHandler, ...), but this feels out of scope for this project.
        @param db_config: DB Configuration to run messages_server with.
        @param db_file: A DB file to store results in.
        @param server_id: The server id associated with current msgs server.
        @param servers_tbl: The table in which we will store "servers".
        @return: A messages_server instance.
        """
        logger = Server.init_logger()
        # DB initialization & extraction of cached tables data:
        db_handler = DatabaseHandler(db_file=db_file, config=db_config,
                                     logger=logger, servers_tbl=servers_tbl)

        server = db_handler.get_server_by_id(server_id=server_id)

        # This will create the tables if not present:
        cached_db_results = db_handler.cache_tables_data()
        # And a protocol to use in our messages_server:
        protocol = ProtocolHandler(db_handler, logger, server=server)
        # Return the initialized messages_server:
        return Server(server, db_handler, protocol, logger)
