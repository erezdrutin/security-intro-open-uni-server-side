from client_side.client import Client
from client_side.consts import AuthRequestCodes, MessagesServerRequestCodes


def main():
    client = Client.initialize_client(
        auth_server_path="srv.info",
        actions=[
            AuthRequestCodes.CLIENT_REGISTRATION,
            AuthRequestCodes.SERVER_REGISTRATION,
            AuthRequestCodes.SERVERS_LIST,
            AuthRequestCodes.GET_AES_KEY,
            MessagesServerRequestCodes.AUTHENTICATE,
            MessagesServerRequestCodes.SEND_MESSAGE
        ])

    # client = Client.initialize_client(
    #     auth_server_path="srv.info",
    #     actions=[
    #         AuthRequestCodes.SERVERS_LIST,
    #         AuthRequestCodes.GET_AES_KEY,
    #         MessagesServerRequestCodes.AUTHENTICATE
    #     ]
    # )

    # client = Client.initialize_client(
    #     auth_server_path="srv.info",
    #     actions=[
    #     ])
    # request = Request(
    #     client_id=client.client_id,
    #     version=Config.VERSION,
    #     code=AuthRequestCodes.SERVER_REGISTRATION,
    #     payload=b'hello world'
    # )
    client.start()


if __name__ == "__main__":
    main()
