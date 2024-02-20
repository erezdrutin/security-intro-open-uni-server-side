from client_side.client import Client
from client_side.config import Config
from common.consts import AuthRequestCodes
from common.models import Request


def main():
    client = Client.initialize_client(me_path="me.info",
                                      auth_server_path="srv.info")

    request = Request(
        client_id=client.client_id,
        version=Config.VERSION,
        code=AuthRequestCodes.SERVER_REGISTRATION,
        payload=b"Your payload here"
    )
    client.send_request(request.to_bytes())


if __name__ == "__main__":
    main()
