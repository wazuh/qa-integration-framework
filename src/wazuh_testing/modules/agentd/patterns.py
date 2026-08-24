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
# A 401 on an already-authenticated request is what actually escalates to re-enrollment
# (bridge_on_reenroll_required(), https_client_bridge.c) -- there is no longer a distinct
# "requesting a key" announcement logged before the attempt itself.
AGENTD_REENROLLING = r'.*credential rejected \(401\); re-enrolling'
# The initial (no pre-existent key) enrollment loop only logs this backoff line after each
# failed attempt (try_enroll_to_server(), start_agent.c); it carries no server IP.
AGENTD_ENROLLMENT_RETRY_BACKOFF = r'.*Sleeping \d+ seconds before trying to enroll again'
AGENTD_MODULE_STOPPED = r'.*Unable to access queue'
AGENTD_TRYING_CONNECT = r'.*Trying to connect to server.*{IP}.*{PORT}'
AGENTD_UNABLE_TO_CONNECT_TO_ANY = r'.*Unable to connect to any server'
# bridge_dispatch_active_response() (https_client_bridge.c) drops an active_response task
# whose payload has no top-level "wazuh" key before it ever reaches execd's queue -- there
# is nothing for execd to log in that case, only this agent-side rejection.
AGENTD_ACTIVE_RESPONSE_MALFORMED_PAYLOAD = r'.*active_response task \S+ has a malformed payload; dropping\.'

ENROLLMENT_INVALID_SERVER = r".*ERROR: \(\d+\): Invalid server address found: '{server_ip}'"
ENROLLMENT_RESOLVE_ERROR = r".*Could not resolve hostname"
