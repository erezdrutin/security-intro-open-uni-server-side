"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Hold a bunch of constant variables which will be used by the client.
"""
from common.consts import MessagesServerRequestCodes, AuthRequestCodes

CLIENT_VERSION = 24
RequestCodeTypes = AuthRequestCodes | MessagesServerRequestCodes
ME_FILE_PATH = "me.info"
AUTH_SERVER_PATH = "srv.info"
