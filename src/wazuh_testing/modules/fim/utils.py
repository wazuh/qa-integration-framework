# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import sys
import os
import hashlib

if sys.platform == 'win32':
    import win32con
    import win32api
    import pywintypes

from .patterns import FIM_EVENT_JSON


from wazuh_testing.constants.paths import WAZUH_PATH


def get_fim_event_data(message: str) -> dict:
    """
    Extracts the JSON data from the callback result of a FIM event.

    Args:
        message (str): The callback result of a FIM event.

    Returns:
        dict: The JSON data of the FIM event.
    """
    to_json = re.match(FIM_EVENT_JSON, message)
    return json.loads(to_json.group(1)).get('data')


def delete_registry(key, sub_key, arch):
    """
    Delete a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """

    try:
        key_h = win32api.RegOpenKeyEx(key, sub_key, 0, win32con.KEY_ALL_ACCESS | arch)
        win32api.RegDeleteTree(key_h, None)
        win32api.RegDeleteKeyEx(key, sub_key, samDesired=arch)
    except OSError as e:
        print(f"Couldn't remove registry key: {e}")
    except pywintypes.error as e:
        print(f"Couldn't remove registry key: {e}")


def create_registry(key, sub_key, arch):
    """
    Create a registry given the key and the subkey.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """

    try:
        win32api.RegCreateKeyEx(key, sub_key, win32con.KEY_ALL_ACCESS | arch)

    except OSError as e:
        print(f"Registry could not be created: {e}")
    except pywintypes.error as e:
        print(f"Registry could not be created: {e}")


def delete_registry_value(key, sub_key, value_name, arch):
    """Delete a registry value from a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        value_name (str): the value to be deleted.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    try:
        key_h = win32api.RegOpenKeyEx(key, sub_key, 0, win32con.KEY_ALL_ACCESS | arch)
        win32api.RegDeleteValue(key_h, value_name)
    except OSError as e:
        print(f"Couldn't remove registry value {value_name}: {e}")
    except pywintypes.error as e:
        print(f"Couldn't remove registry value {value_name}: {e}")


def create_registry_value(key, sub_key, value_name, type, value, arch):
    """
    Modify the content of a registry. If the value doesn't not exists, it will be created.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        value_name (str): the value to be set.
        type (int): type of the value.
        value (str): the content that will be written to the registry value.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    try:
        key_h = win32api.RegOpenKeyEx(key, sub_key, 0, win32con.KEY_ALL_ACCESS | arch)
        win32api.RegSetValueEx(key_h, value_name, 0, type, value)
    except OSError as e:
        print(f"Could not modify registry value content: {e}")
    except pywintypes.error as e:
        print(f"Could not modify registry value content: {e}")


def make_diff_file_path(folder='/testdir1', filename='regular_0'):
    """
    Generate diff file path.

    Parameters
    ----------
    folder : str, optional
        Containing folder. Default `/testdir1`
    filename : str, optional
        File name. Default `regular_0`

    Returns
    -------
    diff_file_path : str
        Path to compressed file.
    """

    file_path = os.path.join(folder, filename)
    if sys.platform == 'win32':
        file_path = file_path.lower()
    sha_1 = hashlib.sha1()
    sha_1.update(file_path.encode('utf-8'))
    file_sha1 = sha_1.hexdigest()

    diff_file_path = os.path.join(WAZUH_PATH, 'queue', 'diff', 'file', file_sha1, 'last-entry.gz')

    return diff_file_path
