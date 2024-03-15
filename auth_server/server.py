"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Define the overall structure of an authentication server.
"""
from __future__ import annotations
import logging
import socket
import threading
from typing import Dict, Any
from common.consts import AuthRequestCodes, DEFAULT_PORT
from common.custom_exceptions import ClientDisconnectedError
from common.file_handler import FileHandler
from server_common.db_handler import DatabaseHandler
from common.models import ServerState
from protocol_handler import ProtocolHandler


class Server:
    def __init__(self, port: int, db_handler: DatabaseHandler,
                 state: ServerState, protocol: ProtocolHandler,
                 logger: logging.Logger):
        """
        Initializes the server with the specified port, database handler,
        server state, protocol handler, and logger.
        @param port: The port on which the server will listen for connections.
        @param db_handler: A DatabaseHandler for interacting with the DB.
        @param state: A ServerState representing the state of the server.
        @param protocol: A ProtocolHandler for handling incoming messages.
        @param logger: A logging.Logger object for logging messages.
        """
        self.port = port
        self.db_handler = db_handler
        self.server_socket = None
        self.state: ServerState = state
        self.protocol: ProtocolHandler = protocol
        self.logger = logger

    def _handle_client(self, client_socket: socket.socket) -> None:
        """
        Manages communication with a connected client until disconnection
        or an error occurs.
        @param client_socket: The client's socket connection to read messages
        from and send responses to.
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
        Initiates the server to start accepting client connections on the
        configured port. This method sets up the server socket and listens for
        incoming connections indefinitely, creating a thread for each client.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port))
        # Queuing up to 5 requests at a time:
        self.server_socket.listen(5)
        self.logger.info(
            f"Server started on port {self.port}. Waiting for connections...")

        while True:
            client_socket, addr = self.server_socket.accept()
            self.logger.warning(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self._handle_client,
                                             args=(client_socket,))
            client_thread.start()

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
    def initialize_server(
            db_config: Dict[str, Dict[str, Any]], db_file: str,
            port_path: str, client_tbl: str, servers_tbl: str) -> Server:
        """
        Creates and returns a server instance configured with a database,
        logger, and server state.
        @param db_config: Database configuration details.
        @param db_file: Path to the database file.
        @param port_path: Path to the file containing the port configuration.
        @param client_tbl: Name of the table for client information in the DB.
        @param servers_tbl: Name of the table for server information in the DB.
        @return: An instance of the configured Server.
        """
        logger = Server.init_logger(logger_level=logging.DEBUG)
        port_config_loader = FileHandler(port_path, logger=logger)
        port = int(port_config_loader.load_value(default_value=DEFAULT_PORT))

        # DB initialization & extraction of cached tables data:
        db_handler = DatabaseHandler(db_file=db_file, config=db_config,
                                     logger=logger, client_tbl=client_tbl,
                                     servers_tbl=servers_tbl)
        # This will create the tables if not present:
        cached_db_results = db_handler.cache_tables_data()
        # Defining a state in which the clients & files will be stored:
        state = ServerState(clients=cached_db_results.get('clients'),
                            servers=cached_db_results.get('servers'))
        # And a protocol to use in our messages_server:
        protocol = ProtocolHandler(db_handler, logger)
        # Return the initialized messages_server:
        return Server(port, db_handler, state, protocol, logger)
