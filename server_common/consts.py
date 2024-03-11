"""
Author: Erez Drutin
Date: 09.03.2024
Purpose: Define consts variables which will be shared across all servers,
both Auth & Message servers.
"""
# The path in which the project's DB will be stored:
DB_FILE_PATH = "../server_common/sec-intro.db"

# DB related definitions:
MESSAGE_SERVERS_TABLE = "message_servers"
ID_SIZE = 16
NAME_SIZE = 255
AES_KEY_SIZE = 16
MESSAGE_SERVERS_IP_SIZE = 4
MESSAGE_SERVERS_PORT_SIZE = 2
MESSAGE_SERVERS_VERSION_SIZE = 1

# Both auth and message servers need access to the following table:
DB_CONFIG = {
    MESSAGE_SERVERS_TABLE: {
        "create_command": f"CREATE TABLE IF NOT EXISTS {MESSAGE_SERVERS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, IP BLOB({MESSAGE_SERVERS_IP_SIZE}) NOT NULL, port INTEGER({MESSAGE_SERVERS_PORT_SIZE}) NOT NULL, version INTEGER({MESSAGE_SERVERS_VERSION_SIZE}) NOT NULL, AESKey BLOB({AES_KEY_SIZE}) NULL)",
        "get_servers": f"SELECT * FROM {MESSAGE_SERVERS_TABLE}",
        "fetch_init": f"SELECT * FROM {MESSAGE_SERVERS_TABLE}",
        "add_server": f"INSERT INTO {MESSAGE_SERVERS_TABLE} (ID, name, IP, port, version, AESKey) VALUES (:id, :name, :ip, :port, :version, :aes_key)",
        "get_server_by_id": f"SELECT * FROM {MESSAGE_SERVERS_TABLE} WHERE ID=:id",
        "data_class": "Server"
    }
}
