"""
Author: Erez Drutin
Date: 04.11.2023
Purpose: A file populated with constant values and enums that will be used
throughout the entire code-base.
"""
from enum import Enum

# General consts for protocol and file handling:
DEFAULT_PORT = 1256
SERVER_VERSION = '24'
FILES_STORAGE_FOLDER = "./storage"
FILES_TABLE = "files"


# Following code definitions will allow us to safely share these variables
# across the client_side, auth & messages servers:
class AuthRequestCodes(Enum):
    CLIENT_REGISTRATION = 1024
    SERVER_REGISTRATION = 1025
    SERVERS_LIST = 1026
    GET_AES_KEY = 1027
    GENERAL_ERROR = 1609
    # Not real request codes as request codes are positive integers. These
    # are mainly for BE purposes as we perform validations on client_side input:
    INVALID_VERSION = -1
    INVALID_CODE = -2


class AuthResponseCodes(Enum):
    REGISTRATION_SUCCESS = 1600
    REGISTRATION_FAILED = 1601
    SERVERS_LIST = 1602
    AES_KEY = 1603
    GENERAL_ERROR = 1609


class MessagesServerRequestCodes(Enum):
    AUTHENTICATE = 1028
    SEND_MESSAGE = 1029
    GENERAL_ERROR = 1609
    # Not real request codes as request codes are positive integers. These
    # are mainly for BE purposes as we perform validations on client_side input:
    INVALID_VERSION = -1
    INVALID_CODE = -2


class MessagesServerResponseCodes(Enum):
    AUTHENTICATE_SUCCESS = 1604
    SEND_MESSAGE_SUCCESS = 1605
    GENERAL_ERROR = 1609


# DB related definitions:
# CLIENTS_TABLE = "clients"
# MESSAGE_SERVERS_TABLE = "message_servers"
# ID_SIZE = 16
# NAME_SIZE = 255
# CLIENTS_PUB_KEY_SIZE = 160
# CLIENTS_AES_KEY_SIZE = 16
# MESSAGE_SERVERS_IP_SIZE = 4
# MESSAGE_SERVERS_PORT_SIZE = 2

# DB_CONFIG = {
#     CLIENTS_TABLE: {
#         "create_command": f"CREATE TABLE IF NOT EXISTS {CLIENTS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, PasswordHash BLOB({CLIENTS_PUB_KEY_SIZE}) NULL, LastSeen DATETIME NOT NULL)",
#         "get_client": f"SELECT * FROM {CLIENTS_TABLE} WHERE name=:name",
#         "add_client": f"INSERT INTO {CLIENTS_TABLE} (ID, name, PasswordHash, LastSeen) VALUES (:id, :name, :password_has, :last_seen)",
#         "update_client_last_seen": f"UPDATE {CLIENTS_TABLE} SET LastSeen=:last_seen WHERE ID=:id",
#         "fetch_init": f"SELECT * FROM {CLIENTS_TABLE}",
#         "get_client_aes": f"SELECT AESKey FROM {CLIENTS_TABLE} WHERE ID=:id",
#         "update_public_aes": f"UPDATE {CLIENTS_TABLE} SET PublicKey=:public_key, AESKey=:aes_key, LastSeen=:last_seen WHERE ID=:id",
#         "data_class": "Client"
#     },
#     MESSAGE_SERVERS_TABLE: {
#         "create_command": f"CREATE TABLE IF NOT EXISTS {MESSAGE_SERVERS_TABLE} (ID BLOB({ID_SIZE}) PRIMARY KEY, name TEXT({NAME_SIZE}) NOT NULL, IP BLOB({MESSAGE_SERVERS_IP_SIZE}) NOT NULL, port BLOB({MESSAGE_SERVERS_PORT_SIZE}) NOT NULL)",
#         "get_message_servers": f"SELECT * FROM {MESSAGE_SERVERS_TABLE}"
#     },
#     FILES_TABLE: {
#         "create_command": f"CREATE TABLE IF NOT EXISTS {FILES_TABLE} (ID BLOB({ID_SIZE}) NOT NULL, Filename TEXT(255) NOT NULL, Pathname TEXT(255) NOT NULL, Verified BOOLEAN NOT NULL, FOREIGN KEY(ID) REFERENCES clients(ID), UNIQUE(ID, Filename))",
#         "fetch_init": f"SELECT * FROM {FILES_TABLE}",
#         "add_file": f"INSERT INTO {FILES_TABLE} (ID, Filename, Pathname, Verified) VALUES (:id, :file_name, :path_name, :verified)",
#         "modify_file_verified": f"UPDATE {FILES_TABLE} SET Verified=:verified WHERE ID=:id AND FileName=:file_name",
#         "data_class": "File"
#     }
# }
