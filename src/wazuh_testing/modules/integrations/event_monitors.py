# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh_testing.tools.file_monitor import generate_callback

def detect_wrong_content_config(error_type, tag, integration, file_monitor):
    """Detect module integration starts after restarting Wazuh.

    Args:
        error_type (str): Type of error found in logs
        tag (str): Name of the setting that cause the error
        integration (str): Integration name
        file_monitor (FileMonitor): File log monitor to detect events
    """   
    callback = f".*ERROR: '{error_type}' content for tag '{tag}' at module '{integration}'."
    
    return file_monitor.start(timeout=10, callback=generate_callback(callback))

def detect_integration_start(integration, file_monitor):
    """Detect module GitHub starts after restarting Wazuh.

    Args:
        integration (str): Integration name
        file_monitor (FileMonitor): File log monitor to detect events
    """
    callback = f".*INFO: Module {integration} started."

    file_monitor.start(timeout=60, callback=generate_callback(callback))





def callback_detect_enabled_err(line):
    if f"ERROR: Invalid content for tag 'enabled' at module 'GitHub'." in line:
        return line
    return None


def callback_detect_only_future_events_err(integration,line):
    if f"ERROR: Invalid content for tag 'only_future_events' at module 'GitHub'." in line:
        return line
    return None


def callback_detect_interval_err(integration, line):
    if f"ERROR: Invalid content for tag 'interval' at module 'GitHub'." in line:
        return line
    return None


def callback_detect_curl_max_size_err(integration, line):
    if f"ERROR: Invalid content for tag 'curl_max_size' at module 'GitHub'. The minimum value allowed is 1KB." in line:
        return line
    return None


def callback_detect_time_delay_err(integration, line):
    if f"ERROR: Invalid content for tag 'time_delay' at module 'GitHub'." in line:
        return line
    return None


def callback_detect_org_name_err(integration, line):
    if f'ERROR: Empty content for tag \'org_name\' at module \'GitHub\'.' in line:
        return line
    return None


def callback_detect_api_token_err(integration, line):
    if f'ERROR: Empty content for tag \'api_token\' at module \'GitHub\'.' in line:
        return line
    return None


def callback_detect_event_type_err(integration, line):
    if f'ERROR: Invalid content for tag \'event_type\' at module \'GitHub\'.' in line:
        return line
    return None


def callback_detect_read_err(integration, line):
    if f'ERROR: Empty content for tag \'api_auth\' at module \'GitHub\'.' in line:
        return line
    return None


def callback_detect_github_start(integration, line):
    if f'INFO: Module GitHub started.' in line:
        return line
    return None

