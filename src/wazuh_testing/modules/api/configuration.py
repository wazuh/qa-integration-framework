"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from pathlib import Path

from wazuh_testing.constants.paths.configurations import WAZUH_API_CONFIGURATION_PATH, WAZUH_SECURITY_CONFIGURATION_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.utils.file import read_yaml, append_content_to_yaml, remove_file, truncate_file, write_file


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
    target_file = set_target_configuration_file(configuration_type)

    return read_yaml(target_file) if Path(target_file).exists() else None


def append_configuration(wazuh_api_configuration_content: dict, configuration_type: str = 'base') -> None:
    """Write a new configuration at the end of the Wazuh API configuration file.

    Args:
        configuration_type (str): Choose configuration file to be removed.
        wazuh_api_configuration_content (dict): Content to be written in the given file.
    """
    target_file = set_target_configuration_file(configuration_type)
    if not Path(target_file).exists():
        write_file(target_file)

    if wazuh_api_configuration_content is None:
        truncate_file(target_file)
    else:
        append_content_to_yaml(target_file, wazuh_api_configuration_content)


def delete_configuration_file(configuration_type: str = 'base') -> None:
    """Delete chosen Wazuh API configuration file.

    Args:
        configuration_type (str): Choose configuration file to be removed.
    """
    remove_file(set_target_configuration_file(configuration_type))
