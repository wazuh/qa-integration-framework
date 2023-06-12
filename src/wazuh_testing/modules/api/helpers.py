"""
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import json
import time
import requests
from base64 import b64encode
from urllib3 import disable_warnings, exceptions

from wazuh_testing import session_parameters
from wazuh_testing.modules.api.constants import API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASSWORD, LOGIN_ROUTE
from wazuh_testing.modules.api.patterns import API_LOGIN_ERROR_MSG


# Variables
base_headers = {'Content-Type': 'application/json'}

disable_warnings(exceptions.InsecureRequestWarning)

# Functions

def generate_bearer_token(user: str = None, password: str = None) -> bytes:
    """Generate a Bearer token.

    Args:
        user (str): User to generate the token.
        password (str): Password to generate the token.

    Returns:
        bearer_token (bytes): Encoded bearer token.
    """
    return b64encode(f"{user}:{password}".encode())


def get_base_url(protocol: str = API_PROTOCOL, host: str = API_HOST, port: str = API_PORT) -> str:
    """Get Wazuh API's base URL.

    Args:
        protocol (str): Protocol used to communicate with the API.
        host (str): Host where the API is receiving requests.
        port (str): Port where the API is listening.

    Returns:
        base_url (str): Wazuh API's base URL
    """

    return f"{protocol}://{host}:{port}"


def set_authentication_header(user: str = None, password: str = None) -> None:
    """Set Authentication header.

    Args:
        user (str): User to login to the API.
        password (str): Password to login to the API.
    """
    user = API_USER if user is None else user
    password = API_PASSWORD if password is None else password
    _token = generate_bearer_token(user, password)

    base_headers['Authorization'] = f'Basic {_token.decode()}'


def login(user: str = API_USER, password: str = API_PASSWORD, timeout: int = session_parameters.default_timeout,
          login_attempts: int = 1, sleep_time: int = 0) -> str:
    """Login to the API and get the token.

    Args:
        user (str): User to login to the API.
        host (str): Password to login to the API.
        timeout (int): Request timeout.
        login_attempts (int): Login attempts before raising a RuntimeError.
        sleep_time (time): Time to sleep before executing the next attempt.

    Returns:
        login_token (str): Login token.

    Raises:
        RuntimeError: When the login was not successful after `login_attempts` every `sleep_time`
    """
    url = f"{get_base_url()}{LOGIN_ROUTE}"
    set_authentication_header(user, password)

    for _ in range(login_attempts):
        response = requests.post(url, headers=base_headers, verify=False, timeout=timeout)

        if response.status_code == 200:
            return json.loads(response.content.decode())['data']['token']
        else:
            time.sleep(sleep_time)

    raise RuntimeError(API_LOGIN_ERROR_MSG, response.json())
