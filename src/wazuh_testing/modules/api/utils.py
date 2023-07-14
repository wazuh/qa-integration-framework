"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import json
import os
import time
import requests
from base64 import b64encode
from copy import deepcopy
from jsonschema import validate
from typing import Tuple, Union, List

from wazuh_testing import session_parameters
from wazuh_testing.constants.api import WAZUH_API_PROTOCOL, WAZUH_API_HOST, WAZUH_API_PORT, WAZUH_API_USER, \
                                        WAZUH_API_PASSWORD, LOGIN_ROUTE, USERS_ROUTE, RESOURCE_ROUTE_MAP, \
                                        TARGET_ROUTE_MAP
from wazuh_testing.constants.paths.api import WAZUH_API_CERTIFICATE
from wazuh_testing.modules.api.patterns import API_LOGIN_ERROR_MSG
from wazuh_testing.utils.file import read_json_file


# Variables
BASE_HEADERS = {'Content-Type': 'application/json'}


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
          host: str = WAZUH_API_HOST, port: str = WAZUH_API_PORT, protocol: str = WAZUH_API_PROTOCOL
          ) -> Tuple[dict, requests.Response]:
    """Login to the API and get the token with the complete response.

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
        response (requests.Response): Response object.

    Raises:
        RuntimeError(msg, requests.Response): When could not login after `login_attempts` every `sleep_time`
    """
    url = f"{get_base_url(protocol=protocol, host=host, port=port)}{LOGIN_ROUTE}"

    for _ in range(login_attempts):
        response = requests.post(url, headers=set_authorization_header(user, password), verify=WAZUH_API_CERTIFICATE, timeout=timeout)

        if response.status_code == 200:
            token = json.loads(response.content.decode())['data']['token']
            authentication_headers = deepcopy(BASE_HEADERS)
            authentication_headers['Authorization'] = f"Bearer {token}"

            return authentication_headers, response
        else:
            time.sleep(sleep_time)

    raise RuntimeError(API_LOGIN_ERROR_MSG, response)


def allow_user_to_authenticate(user_id: str = None) -> requests.Response:
    """Allow a user to perform an authentication in the API.

    Args:
        user_id (str): ID of the target user.
    """
    authentication_headers = login()[0]
    url = get_base_url() + USERS_ROUTE + f'/{user_id}/run_as'
    params = '?allow_run_as=true'

    response = requests.put(url + params, headers=authentication_headers, verify=WAZUH_API_CERTIFICATE)

    return response


def manage_security_resources(method: str = 'get', resource: Union[dict, str] = None,
                              params_values: dict = None) -> requests.Response:
    """Get all information about a security resource.

    Args:
        method (str): Request method.
        resource (dict or str): Resource to be managed. If dict, the value is the payload.
        params_values (dict): Key-value variable where each key is a param.

    Returns:
        response (requests.Response): Response of the request performed.
    """
    if isinstance(resource, dict):
        key = list(resource.keys())[0]
        payload = resource[key]
    else:
        key = resource if resource is not None else list(params_values.keys())[0]
        payload = None

    try:
        if len(params_values) > 1:
            raise ValueError('params_values must contain only 1 element')
    except TypeError:
        pass

    params = ''
    if isinstance(params_values, type(None)) and method == 'update':
        raise ValueError('params_values must be a dict containing 1 element')
    elif method != 'update':
        params = f"?{key}={params_values[key]}" if params_values is not None else params
    else:
        method = 'put'
        params = f"/{params_values[key]}"

    url = get_base_url() + RESOURCE_ROUTE_MAP[key] + params

    authentication_headers = login()[0]
    response = getattr(requests, method)(url, headers=authentication_headers, verify=WAZUH_API_CERTIFICATE, json=payload)

    return response


def add_resources(test_metadata: dict) -> dict:
    """Add the security resources using the API.

    Args:
        test_metadata (dict): Test metadata.
    """
    resources = test_metadata['resources']

    for resource in resources:
        test_metadata['resources_ids'][resource] = list()
        for payload in resources[resource]:
            response = manage_security_resources('post', resource={resource: payload})
            if response.status_code != 200 or response.json()['error'] != 0:
                raise RuntimeError(f"Could not add {resource}.\nFull response: {response.text}")
            resource_id = response.json()['data']['affected_items'][0]['id']
            # Enable authentication for the new user
            if resource == 'user_ids':
                allow_user_to_authenticate(resource_id)
            # Set the resource ID for the test to use it
            test_metadata['resources_ids'][resource].append(resource_id)
            try:
                if test_metadata['target_resource']['name'] == resource:
                    test_metadata['target_resource']['id'] = resource_id
            except KeyError:
                pass

    return test_metadata


def remove_resources(test_metadata: dict) -> None:
    """Remove the security resources using the API.

    Args:
        test_metadata (dict): Test metadata.
    """
    resources = test_metadata['resources']

    for resource in resources:
        response = manage_security_resources('delete', params_values={resource: 'all'})
        if response.status_code != 200 or response.json()['error'] != 0:
            raise RuntimeError(f"Could not remove {resource}.\nFull response: {response.text}")


def relate_resources(test_metadata: dict) -> None:
    """Relate security resources.

    Args:
        test_metadata (dict): Test metadata.
    """
    resources_ids = test_metadata['resources_ids']
    relationships = test_metadata['relationships']
    # Continue if there are not extra params
    try:
        # Extra parameters must be the same length as the target values
        extra_params = test_metadata['extra_params']
    except KeyError:
        extra_params = None

    for origin in relationships:
        # It is only allowed to relate 1 (one) origin with many targets
        origin_id = resources_ids[origin][0]
        target_param = relationships[origin]
        target_values = resources_ids[target_param]
        target_route = TARGET_ROUTE_MAP[target_param]
        # Relate each target value with the origin
        for idx, target_value in enumerate(target_values):
            route_and_params = f"/{origin_id}/{target_route}?{target_param}={target_value}"
            if extra_params is not None:
                route_and_params += f"&{extra_params[idx]}"
            url = get_base_url() + RESOURCE_ROUTE_MAP[origin] + route_and_params
            # Relate the origin resource with the target resource
            response = requests.post(url, headers=login()[0], verify=WAZUH_API_CERTIFICATE)
            if response.status_code != 200 or response.json()['error'] != 0:
                raise RuntimeError(f"Could not relate {origin}: {origin_id} with {target_param}: {target_value}."
                                   f"\nResponse: {response.text}")


def remove_resources_relationship(origin_resource: dict = None, target_resource: dict = None) -> dict:
    """Remove relationship between security resources.

    Args:
        origin_resource (str): Resource from where the relationship will be removed. E.g: {'user_ids': '1'}
        target_resource (str): Relationship that will be removed. E.g: {'role_ids': '1'}
    """
    origin_name = list(origin_resource.keys())[0]
    origin_id = origin_resource[origin_name]
    origin_route = RESOURCE_ROUTE_MAP[origin_name]
    target_name = list(target_resource.keys())[0]
    target_id = target_resource[target_name]
    target_route = TARGET_ROUTE_MAP[target_name]
    route_and_params = f"/{origin_id}/{target_route}?{target_name}={target_id}"
    url = get_base_url() + origin_route + route_and_params

    # Remove relationship between the origin resource and the target resource
    response = requests.delete(url, headers=login()[0], verify=WAZUH_API_CERTIFICATE)
    if response.status_code != 200 or response.json()['error'] != 0:
        raise RuntimeError(f"Could not remove relationship between {origin_name}: {origin_id} "
                            f"and {target_name}: {target_id}."
                            f"\nResponse: {response.text}")


def get_resource_admin_ids(response: requests.Response) -> List:
    """Get the ID of each item (if it is an admin resource) in the response.

    Args:
        response (requests.Response): Response object.

    Return:
        item_ids (list): List of ids.
    """
    items = response.json()['data']['affected_items']

    items_ids = [item['id'] for item in items if item['id'] < 100]

    return items_ids


def validate_statistics(response: requests.Response, schema_path: Union[str, os.PathLike]):
    """Validate statistics coming from the response object.

    Args:
        response (requests.Response): API response containing the statistics.
        schema_path (str or os.PathLike): Path of the schema from which the response will be validated.
    """
    stats_schema = read_json_file(schema_path)
    validate(instance=response.json(), schema=stats_schema)
