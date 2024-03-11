"""
Author: Erez Drutin
Date: 11.03.2024
Purpose: Act as the main entry point for the client execution process.
"""
from client_side.factory import ClientFactory, ClientType


def main():
    client = ClientFactory().create_client(
        option=ClientType.MESSAGE_SERVER_FULL_FLOW)
    client.start()


if __name__ == "__main__":
    main()
