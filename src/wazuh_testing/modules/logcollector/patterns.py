# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX

# Callback patterns to find events in log file.
LOGCOLLECTOR_ANALYZING_FILE = r'.*Analyzing file: \'{file}\''
LOGCOLLECTOR_MONITORING_COMMAND = r'.*INFO: Monitoring output of command\(\d+\): {command}'
LOGCOLLECTOR_MONITORING_FULL_COMMAND = r'.*INFO: Monitoring full output of command\(\d+\): {command}'
LOGCOLLECTOR_READING_COMMAND_ALIAS = r'.*Reading command message: \'ossec: output: \'{alias}\'.*'
LOGCOLLECTOR_SOCKET_TARGET_VALID = r'.*DEBUG: Socket target for \'{location}\' -> {socket_name}'
LOGCOLLECTOR_SOCKET_TARGET_NOT_DEFINED = r'.*CRITICAL: Socket \'{socket_name}\' for \'{location}\' is not defined.'
LOGCOLLECTOR_LOG_TARGET_NOT_FOUND = r'.*WARNING: Log target \'{socket_name}\' not found for the output format of localfile \'{location}\'.'

ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
ERROR_CONFIGURATION = 'The expected configuration was not found in the module configuration response'
ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"
ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
