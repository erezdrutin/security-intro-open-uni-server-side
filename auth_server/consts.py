from common.consts import *
from server_common.consts import *

# Request / Response Codes definitions:
RequestCodes = AuthRequestCodes
ResponseCodes = AuthResponseCodes

# Ticket related attributes:
TICKET_TTL_SEC = 60 * 10  # 10 minutes

# DB related definitions:
CLIENTS_TABLE = "clients"
CLIENTS_PUB_KEY_SIZE = 160

DB_CONFIG = {
    CLIENTS_TABLE: {
        "create_command": f"CREATE TABLE IF NOT EXISTS {CLIENTS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, PasswordHash BLOB({AES_KEY_SIZE}) NULL, LastSeen DATETIME NOT NULL)",
        "get_client_by_name": f"SELECT * FROM {CLIENTS_TABLE} WHERE name=:name",
        "get_client_by_id": f"SELECT * FROM {CLIENTS_TABLE} WHERE ID=:id",
        "add_client": f"INSERT INTO {CLIENTS_TABLE} (ID, name, PasswordHash, LastSeen) VALUES (:id, :name, :password_hash, :last_seen)",
        "update_client_last_seen": f"UPDATE {CLIENTS_TABLE} SET LastSeen=:last_seen WHERE ID=:id",
        "fetch_init": f"SELECT * FROM {CLIENTS_TABLE}",
        "data_class": "Client"
    },
    **DB_CONFIG
}
