# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Callback patterns to find events in log file.
from . import PREFIX

INVALID_VALUE_FOR_ELEMENT = fr"{PREFIX}.*Invalid value for element.*"
CONFIGURATION_ERROR = r".*{severity}:.*Configuration error at '{path}'.*"

INVALID_VALUE_FOR_PORT_NUMBER = fr"{PREFIX}.*Invalid port number.*"

IGNORED_INVALID_PROTOCOL = r".*WARNING:.* Ignored invalid value '{protocol}' for 'protocol'.*"
ERROR_GETTING_PROTOCOL = fr"{PREFIX}.* Error getting protocol. Default value \(TCP\) will be used.*"
DETECT_REMOTED_STARTED = r".*Started.*Listening on port {port}\/{protocol_valid_upper} \({connection}\).*"

ERROR_BIND_PORT = r".*CRITICAL: \(\d+\): Unable to Bind port '1514' due to \[\(\d+\)\-\(Transport endpoint is not connected\)\]"

WARNING_QUEUE_SIZE_TOO_BIG = r".*WARNING: Queue size is very high. The application may run out of memory."

WARNING_INVALID_VALUE_FOR = r".*WARNING: \(\d+\): Invalid value '.*' in '{option}' option. Default value will be used.*"

ARCHIVES_FULL_LOG  = r'.*{location}.*{message}.*'

KEY_UPDATE = r'.*rem_keyupdate_main().*Checking for keys file changes.*'

ACK_MESSAGE = r".*#!-agent ack.*"

ACTIVE_RESPONSE_RECEIVED = r'.*DEBUG: Active response request received:.*'

ACTIVE_RESPONSE_SENT = r'.*DEBUG: Active response sent: #!-execd.*'

EXECD_MESSAGE = r".*#!-execd {message}.*"

START_UP = r".*DEBUG: Agent {agent_name} sent HC_STARTUP from '{agent_ip}'"

MERGED_NEW_SHARED_END_SEND= r".*End sending file.*to agent.*"
