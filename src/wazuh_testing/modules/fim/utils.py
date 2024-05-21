# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import sys

if sys.platform == 'win32':
    import win32con
    import win32api
    import pywintypes

from .patterns import FIM_EVENT_JSON


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
