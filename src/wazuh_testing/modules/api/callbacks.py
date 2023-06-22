"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
from typing import Union

from wazuh_testing.constants.paths.api import WAZUH_API_LOG_FILE_PATH
from wazuh_testing.constants.api import WAZUH_API_USER, LOGIN_ROUTE
from wazuh_testing.modules.api.patterns import API_TIMEOUT_ERROR_MSG, API_LOGIN_REQUEST_MSG
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils.callbacks import generate_callback


def search_timeout_error(file_to_monitor: Union[str, os.PathLike] = WAZUH_API_LOG_FILE_PATH) -> None:
    """Search for API timeout error in logs.

    Args:
        file_to_monitor (str | os.PathLike): File in which to search for the message

    Raises:
        RuntimeError: When the log was not found.
    """
    monitor_timeout_error = file_monitor.FileMonitor(file_to_monitor)
    monitor_timeout_error.start(callback=generate_callback(API_TIMEOUT_ERROR_MSG))

    if monitor_timeout_error.callback_result is None:
        raise RuntimeError('The timeout error did not appear.')

    return monitor_timeout_error.callback_result


def search_login_request(file_to_monitor: Union[str, os.PathLike] = WAZUH_API_LOG_FILE_PATH, user: str = WAZUH_API_USER,
                         host: str = '127.0.0.1') -> None:
    """Search for API timeout error in logs.

    Args:
        file_to_monitor (str | os.PathLike): File in which to search for the message
        user (str): Wazuh API user
        host (str): Wazuh API host

    Raises:
        RuntimeError: When the log was not found.
    """
    monitor_login_request_message = file_monitor.FileMonitor(file_to_monitor)
    monitor_login_request_message.start(callback=generate_callback(API_LOGIN_REQUEST_MSG, {
            'user': user,
            'host': host,
            'login_route': LOGIN_ROUTE
        })
    )

    if monitor_login_request_message.callback_result is None:
        raise RuntimeError('The login request message did not appear.')

    return monitor_login_request_message.callback_result
