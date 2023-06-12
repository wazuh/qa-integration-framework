"""
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
from copy import deepcopy
from typing import Union

from wazuh_testing.constants.paths.configurations import WAZUH_API_CONFIGURATION_PATH, WAZUH_SECURITY_CONFIGURATION_PATH
from wazuh_testing.utils.configuration import expand_placeholders, add_metadata
from wazuh_testing.utils.file import read_yaml, append_content_to_yaml, delete_file


allowed_types = ('base', 'security')


def check_configuration_type(configuration_type: str) -> None:
    """Check if the configuration type is allowed.

    Args:
        configuration_type (str): Configuration type.

    Raises:
        RuntimeError: When the configuration type is not allowed.
    """
    if configuration_type not in allowed_types:
        raise RuntimeError(f"The chosen option is not allowed, use one of these: {allowed_types}")


def set_target_configuration_file(configuration_type: str) -> str:
    """Set the target configuration filepath where the actions will be performed.

    Args:
        configuration_type (str): Configuration type.

    Returns:
        wazuh_api_configuration_path (str): Path to the chosen Wazuh API configuration file.
    """
    check_configuration_type(configuration_type)
    configuration_files = {'base': WAZUH_API_CONFIGURATION_PATH, 'security': WAZUH_SECURITY_CONFIGURATION_PATH}
    wazuh_api_configuration_path = configuration_files[configuration_type]

    return wazuh_api_configuration_path


def get_configuration(configuration_type: str = 'base') -> dict:
    """Get current content from the chosen Wazuh API configuration file.

    Args:
        configuration_type (str): Choose file from which the configuration will be obtained.

    Returns:
        current_configuration (dict): Current content of the `api.yaml` file.
    """
    return read_yaml(set_target_configuration_file(configuration_type))


def append_configuration(wazuh_api_configuration_content: dict, configuration_type: str = 'base') -> None:
    """Write a new configuration at the end of the Wazuh API configuration file.

    Args:
        configuration_type (str): Choose configuration file to be removed.
        wazuh_api_configuration_content (dict): Content to be written in the given file.
    """
    append_content_to_yaml(set_target_configuration_file(configuration_type), wazuh_api_configuration_content)


def delete_configuration_file(configuration_type: str = 'base') -> None:
    """Delete chosen Wazuh API configuration file.

    Args:
        configuration_type (str): Choose configuration file to be removed.
    """
    delete_file(set_target_configuration_file(configuration_type))


def replace_in_api_configuration_template(test_configuration_path: Union[str, os.PathLike] = None,
                                          test_configuration: dict = None, test_metadata: dict = None) -> dict:
    """Replace test case data in the API configuration template.

    The configuration template should have placeholders in uppercase, for instance:
    ```
    base:
      access:
        block_time: BLOCK_TIME
    ```

    Those placeholders will be replaced by the `test_configuration` values (set in `configuration_parameters` in
    the file containing the test cases information). So, the test case file must have the corresponding replacements
    with its keys in uppercase also, for instance:
    ```
    - name: ...
      description: ...
      configuration_parameters:
        BLOCK_TIME: 10
    ```

    Args:
        test_configuration_path (str | PathLike): Path to the file with the API configuration template.
        test_configuration (dict): Test case configuration data (configuration parameters).
        test_metadata (dict): Test case metadata (optional).

    Returns:
        configuration_with_replacements (dict): Configurations that will be applied in the Wazuh API.
    """
    if None in (test_configuration_path, test_configuration, test_metadata):
        raise TypeError('The configuration template and the configuration parameters must be specified.')

    configuration_with_replacements = {}
    configuration_template = read_yaml(test_configuration_path)

    # Replace configuration parameters (`test_configuration`) in the configuration template.
    configuration_with_replacements = expand_placeholders(deepcopy(configuration_template), test_configuration[0])

    if test_metadata is not None:
        add_metadata(test_metadata)

    return [configuration_with_replacements]
