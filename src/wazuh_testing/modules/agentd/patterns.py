# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
AGENTD_CONNECTED_TO_SERVER = fr'{PREFIX} Connected to the server'
AGENTD_UPDATING_STATE_FILE = r".*Updating state file"
AGENTD_SENDING_KEEP_ALIVE = r".*Sending keep alive"
AGENTD_SENDING_AGENT_NOTIFICATION = r".*Sending agent notification"
AGENTD_RECEIVED_ACK = r".*Received message: '#!-agent ack"
AGENTD_RECEIVED_VALID_KEY = r".*Valid key received"
AGENTD_REQUESTING_KEY = r".*Valid key received"
AGENTD_MODULE_STOPPED = r".*Unable to access queue"