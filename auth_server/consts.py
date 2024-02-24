from common.consts import *

# Request / Response Codes definitions:
RequestCodes = AuthRequestCodes
ResponseCodes = AuthResponseCodes

# Ticket related attributes:
TICKET_TTL_SEC = 60 * 10  # 10 minutes

# DB related definitions:
CLIENTS_TABLE = "clients"
MESSAGE_SERVERS_TABLE = "message_servers"
ID_SIZE = 16
NAME_SIZE = 255
CLIENTS_PUB_KEY_SIZE = 160
CLIENTS_AES_KEY_SIZE = 16
MESSAGE_SERVERS_IP_SIZE = 4
MESSAGE_SERVERS_PORT_SIZE = 2
MESSAGE_SERVERS_VERSION_SIZE = 1

DB_CONFIG = {
    CLIENTS_TABLE: {
        "create_command": f"CREATE TABLE IF NOT EXISTS {CLIENTS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, PasswordHash BLOB({CLIENTS_PUB_KEY_SIZE}) NULL, LastSeen DATETIME NOT NULL)",
        "get_client_by_name": f"SELECT * FROM {CLIENTS_TABLE} WHERE name=:name",
        "get_client_by_id": f"SELECT * FROM {CLIENTS_TABLE} WHERE ID=:id",
        "add_client": f"INSERT INTO {CLIENTS_TABLE} (ID, name, PasswordHash, LastSeen) VALUES (:id, :name, :password_hash, :last_seen)",
        "update_client_last_seen": f"UPDATE {CLIENTS_TABLE} SET LastSeen=:last_seen WHERE ID=:id",
        "fetch_init": f"SELECT * FROM {CLIENTS_TABLE}",
        "data_class": "Client"
    },
    MESSAGE_SERVERS_TABLE: {
        "create_command": f"CREATE TABLE IF NOT EXISTS {MESSAGE_SERVERS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, IP BLOB({MESSAGE_SERVERS_IP_SIZE}) NOT NULL, port INTEGER({MESSAGE_SERVERS_PORT_SIZE}) NOT NULL, version INTEGER({MESSAGE_SERVERS_VERSION_SIZE}) NOT NULL, AESKey BLOB({CLIENTS_AES_KEY_SIZE}) NULL)",
        "get_servers": f"SELECT * FROM {MESSAGE_SERVERS_TABLE}",
        "fetch_init": f"SELECT * FROM {MESSAGE_SERVERS_TABLE}",
        "add_server": f"INSERT INTO {MESSAGE_SERVERS_TABLE} (ID, name, IP, port, version, AESKey) VALUES (:id, :name, :ip, :port, :version, :aes_key)",
        "get_server_by_id": f"SELECT * FROM {MESSAGE_SERVERS_TABLE} WHERE ID=:id",
        "data_class": "Server"
    }
}
