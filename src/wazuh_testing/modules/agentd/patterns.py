# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX

# Callback patterns to find events in log file.
AGENTD_CONNECTED_TO_SERVER = fr'{PREFIX} Connected to the server'
AGENTD_UPDATING_STATE_FILE = r'.*Updating state file'
AGENTD_SENDING_KEEP_ALIVE = r'.*Sending keep alive'
AGENTD_SENDING_AGENT_NOTIFICATION = r'.*Sending agent notification'
AGENTD_RECEIVED_ACK = r".*Received message: '#!-agent ack"
AGENTD_RECEIVED_VALID_KEY = r".*Valid key received"
AGENTD_REQUESTING_KEY = r'.*Requesting a key.*{IP}'
AGENTD_MODULE_STOPPED = r'.*Unable to access queue'
AGENTD_TRYING_CONNECT = r'.*Trying to connect to server.*{IP}.*{PORT}'
AGENTD_UNABLE_TO_CONNECT_TO_ANY = r'.*Unable to connect to any server'
AGENTD_CONNECTED_TO_ENROLLMENT = r'.*Connected to enrollment service at.*{IP}.*{PORT}'
AGENTD_SERVER_RESPONDED = r'.*Server responded. Releasing lock'
AGENTD_SERVER_UNAVAILABLE = r'.*Server unavailable. Setting lock'
AGENTD_UNABLE_TO_CONNECT_ENROLLMENT = r'.*Unable to connect to enrollment service'
AGENTD_UNABLE_TO_CONNECT = r'.*Unable to connect to .*{IP}.*{PORT}'

ENROLLMENT_INVALID_SERVER = r".*ERROR: \(\d+\): Invalid server address found: '{server_ip}'"
ENROLLMENT_RESOLVE_ERROR = r".*ERROR: Could not resolve hostname: {server_ip}"
ENROLLMENT_CONNECTED = r".*Connected to enrollment service at '\[{server_ip}\]:{port}'"
