import logging

import uvicorn
from j_user_auth_svc.app import app
from j_user_auth_svc.config import SERVICE_HOST, SERVICE_PORT


# Set up logging for the application
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    service_host = SERVICE_HOST
    service_port = int(SERVICE_PORT)
    uvicorn.run(app, host=service_host, port=service_port)


if __name__ == "__main__":
    # Entry point for the application
    main()