# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX

# Callback patterns to find events in log file.
# HTTPS transport (wazuh/wazuh#37831): the legacy TCP client's "Connected to the server" line has
# no equivalent on the /control path -- this is the closest milestone, logged once Startup is
# accepted and the client leaves the Starting state (bridge_on_startup_result(), https_client_bridge.c).
AGENTD_HTTPS_STARTUP_ACCEPTED = fr'{PREFIX}.*https_client startup accepted'
AGENTD_UPDATING_STATE_FILE = r'.*Updating state file'
AGENTD_RECEIVED_VALID_KEY = r".*Valid key received"
AGENTD_REQUESTING_KEY = r'.*Requesting a key.*{IP}'
AGENTD_MODULE_STOPPED = r'.*Unable to access queue'
AGENTD_TRYING_CONNECT = r'.*Trying to connect to server.*{IP}.*{PORT}'
AGENTD_UNABLE_TO_CONNECT_TO_ANY = r'.*Unable to connect to any server'
# bridge_dispatch_active_response() (https_client_bridge.c) drops an active_response task
# whose payload has no top-level "wazuh" key before it ever reaches execd's queue -- there
# is nothing for execd to log in that case, only this agent-side rejection.
AGENTD_ACTIVE_RESPONSE_MALFORMED_PAYLOAD = r'.*active_response task \S+ has a malformed payload; dropping\.'

ENROLLMENT_INVALID_SERVER = r".*ERROR: \(\d+\): Invalid server address found: '{server_ip}'"
ENROLLMENT_RESOLVE_ERROR = r".*ERROR: Could not resolve hostname: {server_ip}"
ENROLLMENT_CONNECTED = r".*Connected to enrollment service at '\[{server_ip}\]:{port}'"
