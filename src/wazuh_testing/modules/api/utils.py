"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import json
import os
import requests
from requests.adapters import HTTPAdapter, Retry
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
          timeout: int = session_parameters.default_timeout, login_attempts: int = 3, backoff_factor: float = 0.5,
          host: str = WAZUH_API_HOST, port: str = WAZUH_API_PORT, protocol: str = WAZUH_API_PROTOCOL
          ) -> Tuple[dict, requests.Response]:
    """Login to the API and get the token with the complete response.

    Args:
        user (str): User to login to the API.
        password (str): Password to login to the API.
        timeout (int): Request timeout.
        login_attempts (int): Login attempts before raising a RuntimeError. Default is 3.
        backoff_factor (float): A backoff factor to apply between attempts after the second try. Default is 0.5.
        host (str): Host where the API is receiving requests.
        port (str): Port where the API is listening.

    Returns:
        authentication_headers (dict): Headers required to make a future request.
        response (requests.Response): Response object.

    Raises:
        RuntimeError(msg, requests.Response): When could not login after `login_attempts` every timeout determined by
        the `backoff_factor`.
    """
    url = f"{get_base_url(protocol=protocol, host=host, port=port)}{LOGIN_ROUTE}"

    session = requests.Session()
    retry = Retry(total=None, connect=login_attempts, backoff_factor=backoff_factor)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount(f"{protocol}://", adapter)

    response = session.post(url, headers=set_authorization_header(user, password), verify=WAZUH_API_CERTIFICATE,
                                timeout=timeout)
    if response.status_code == 200:
        token = json.loads(response.content.decode())['data']['token']
        authentication_headers = deepcopy(BASE_HEADERS)
        authentication_headers['Authorization'] = f"Bearer {token}"

        return authentication_headers, response

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


def compare_config_api_response(configuration, section):
    """Assert if configuration values provided are the same that configuration provided for API response.

    Args:
        configuration (dict): Dictionary with Wazuh manager configuration.
        section (str): Section to compare.
    """
    import sys
    from sys import stderr

    api_answer = get_manager_configuration(section=section)
    assert type(api_answer) == type(configuration)

    if isinstance(api_answer, list):
        configuration_length = len(configuration)
        for i in range(configuration_length):
            api_answer_to_compare = dict((key, api_answer[i][key]) for key in configuration[i].keys())
            configuration_to_compare = dict((key, configuration[i][key]['value']) for key in configuration[i].keys())
            assert api_answer_to_compare == configuration_to_compare
    else:
        api_answer_to_compare = dict((key, api_answer[key]) for key in configuration.keys())
        assert api_answer_to_compare == configuration


def get_manager_configuration(section=None, field=None):
    """Get Wazuh manager configuration response from API using GET /manager/configuration

    References: https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/
                api.controllers.manager_controller.get_configuration

    Args:
        section (str): wazuh configuration section, E.g: "active-response", "ruleset"...
        field   (str): section child. E.g, fields for ruleset section are: decoder_dir, rule_dir, etc

    Returns:
        `obj`(str or map): active configuration indicated by Wazuh API. If section and field are selected, it will
         return a String, if not, it will return a map for the section/entire configurations with fields/sections
         as keys.
    """
    api_details = get_api_details_dict()
    api_query = f"{api_details['base_url']}/manager/configuration?"

    if section is not None:
        api_query += f"section={section}"
        if field is not None:
            api_query += f"&field={field}"

    response = requests.get(api_query, headers=api_details['auth_headers'], verify=False)

    assert response.json()['error'] == 0, f"Wazuh API response status different from 0: {response.json()}"
    answer = response.json()['data']['affected_items'][0]

    def get_requested_values(answer, section, field):
        """Return requested value from API response

        Received a section and a field and tries to return all available values that match with this entry.
        This function is required because, sometimes, there may be multiple entries with the same field or section
        and the API will return a list instead of a map. Using recursion we make sure that the output matches
        the user expectations.
        """
        if isinstance(answer, list):
            new_answer = []
            for element in answer:
                new_answer.append(get_requested_values(element, section, field))
            return new_answer
        elif isinstance(answer, dict):
            if section in answer.keys():
                new_answer = answer[section]
                return get_requested_values(new_answer, section, field)
            if field in answer.keys():
                new_answer = answer[field]
                return get_requested_values(new_answer, section, field)
        return answer

    return get_requested_values(answer, section, field)


def get_api_details_dict(protocol=WAZUH_API_PROTOCOL, host=WAZUH_API_HOST, port=WAZUH_API_PORT, user=WAZUH_API_USER, password=WAZUH_API_PASSWORD,
                         login_endpoint=LOGIN_ROUTE, timeout=10, login_attempts=1, sleep_time=0):
    """Get API details"""
    login_token = get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout, login_attempts,
                                      sleep_time)
    return {
        'base_url': get_base_url(protocol, host, port),
        'auth_headers': {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {login_token}'
        }
    }


def get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout, login_attempts, sleep_time):
    """Get API login token"""

    login_url = f"{get_base_url(protocol, host, port)}{login_endpoint}"

    for _ in range(login_attempts):
        response = requests.post(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

        if response.status_code == 200:
            return json.loads(response.content.decode())['data']['token']
        time.sleep(sleep_time)
    else:
        raise RuntimeError(f"Error obtaining login token: {response.json()}")


def get_login_headers(user, password):
    basic_auth = f"{user}:{password}".encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
