# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh_testing.utils.callbacks import generate_callback

def detect_wrong_content_config(error_type, tag, integration, file_monitor):
    """Detect module integration starts after restarting Wazuh.

    Args:
        error_type (str): Type of error found in logs
        tag (str): Name of the setting that cause the error
        integration (str): Integration name
        file_monitor (FileMonitor): File log monitor to detect events
    """   
    callback = f".*ERROR: {error_type} content for tag '{tag}' at module '{integration}'."
    
    return file_monitor.start(timeout=180, callback=generate_callback(callback))

def detect_integration_start(integration, file_monitor):
    """Detect module GitHub starts after restarting Wazuh.

    Args:
        integration (str): Integration name
        file_monitor (FileMonitor): File log monitor to detect events
    """
    callback = f".*INFO: Module {integration} started."

    file_monitor.start(timeout=60, callback=generate_callback(callback))