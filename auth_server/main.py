"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: Execute the program. This is the entry point for our messages_server code.
"""
from auth_server.consts import CLIENTS_TABLE, MESSAGE_SERVERS_TABLE, \
    DB_CONFIG, DB_FILE_PATH
from auth_server.server import Server


def main():
    server = Server.initialize_server(
        db_config=DB_CONFIG, db_file=DB_FILE_PATH, port_path="port.info",
        client_tbl=CLIENTS_TABLE, servers_tbl=MESSAGE_SERVERS_TABLE)
    server.start()


if __name__ == '__main__':
    main()
