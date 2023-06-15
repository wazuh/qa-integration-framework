"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
from copy import deepcopy
from typing import Union

from wazuh_testing.constants.paths.configurations import WAZUH_API_CONFIGURATION_PATH, WAZUH_SECURITY_CONFIGURATION_PATH
from wazuh_testing.modules.api.constants import CONFIGURATION_TYPES
from wazuh_testing.utils.configuration import expand_placeholders, add_metadata
from wazuh_testing.utils.file import read_yaml, append_content_to_yaml, delete_file, truncate_file


def check_configuration_type(configuration_type: str) -> None:
    """Check if the configuration type is allowed.

    Args:
        configuration_type (str): Configuration type.

    Raises:
        RuntimeError: When the configuration type is not allowed.
    """
    if configuration_type not in CONFIGURATION_TYPES:
        raise RuntimeError(f"The chosen option is not allowed, use one of these: {CONFIGURATION_TYPES}")


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
    target_file = set_target_configuration_file(configuration_type)

    if wazuh_api_configuration_content is None:
        truncate_file(target_file)
    else:
        append_content_to_yaml(target_file, wazuh_api_configuration_content)


def delete_configuration_file(configuration_type: str = 'base') -> None:
    """Delete chosen Wazuh API configuration file.

    Args:
        configuration_type (str): Choose configuration file to be removed.
    """
    delete_file(set_target_configuration_file(configuration_type))
