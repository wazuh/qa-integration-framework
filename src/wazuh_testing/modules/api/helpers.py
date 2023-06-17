"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import json
import time
import requests
from base64 import b64encode
from copy import deepcopy
from urllib3 import disable_warnings, exceptions

from wazuh_testing import session_parameters
from wazuh_testing.constants.api import WAZUH_API_PROTOCOL, WAZUH_API_HOST, WAZUH_API_PORT, WAZUH_API_USER, \
                                        WAZUH_API_PASSWORD, LOGIN_ROUTE
from wazuh_testing.modules.api.patterns import API_LOGIN_ERROR_MSG


# Variables
BASE_HEADERS = {'Content-Type': 'application/json'}

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


def get_base_url(protocol: str = WAZUH_API_PROTOCOL, host: str = WAZUH_API_HOST, port: str = WAZUH_API_PORT) -> str:
    """Get Wazuh API's base URL.

    Args:
        protocol (str): Protocol used to communicate with the API.
        host (str): Host where the API is receiving requests.
        port (str): Port where the API is listening.

    Returns:
        base_url (str): Wazuh API's base URL
    """

    return f"{protocol}://{host}:{port}"


def set_authorization_header(user: str = None, password: str = None) -> dict:
    """Set Authorization header.

    Args:
        user (str): User to login to the API.
        password (str): Password to login to the API.

    Returns:
        headers (dict): Headers with authorization included
    """
    user = WAZUH_API_USER if user is None else user
    password = WAZUH_API_PASSWORD if password is None else password
    _token = generate_bearer_token(user, password)
    headers = deepcopy(BASE_HEADERS)
    headers['Authorization'] = f'Basic {_token.decode()}'

    return headers


def login(user: str = WAZUH_API_USER, password: str = WAZUH_API_PASSWORD,
          timeout: int = session_parameters.default_timeout, login_attempts: int = 1, sleep_time: int = 0,
          host: str = WAZUH_API_HOST, port: str = WAZUH_API_PORT) -> dict:
    """Login to the API and get the token.

    Args:
        user (str): User to login to the API.
        password (str): Password to login to the API.
        timeout (int): Request timeout.
        login_attempts (int): Login attempts before raising a RuntimeError.
        sleep_time (time): Time to sleep before executing the next attempt.
        host (str): Host where the API is receiving requests.
        port (str): Port where the API is listening.

    Returns:
        authentication_headers (dict): Headers required to make a future request.

    Raises:
        RuntimeError: When the login was not successful after `login_attempts` every `sleep_time`
    """
    url = f"{get_base_url(host=host, port=port)}{LOGIN_ROUTE}"

    for _ in range(login_attempts):
        response = requests.post(url, headers=set_authorization_header(user, password), verify=False, timeout=timeout)

        if response.status_code == 200:
            authentication_headers = {
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {json.loads(response.content.decode())['data']['token']}"
            }
            return authentication_headers
        else:
            time.sleep(sleep_time)

    raise RuntimeError(API_LOGIN_ERROR_MSG, response.json())
