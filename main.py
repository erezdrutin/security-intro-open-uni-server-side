"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: Execute the program. This is the entry point for our messages_server code.
"""

from const import DB_CONFIG, CLIENTS_TABLE, FILES_TABLE
from server import Server


def main():
    server = Server.initialize_server(
        db_config=DB_CONFIG, db_file="defensive.db", port_path="port.info",
        client_tbl=CLIENTS_TABLE, files_tbl=FILES_TABLE)
    server.start()


if __name__ == '__main__':
    main()
