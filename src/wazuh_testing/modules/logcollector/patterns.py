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
LOGCOLLECTOR_INVALID_VALUE_ELEMENT = r'{prefix}.*ERROR: \(\d+\): Invalid value for element \'{option}\': {value}.'
LOGCOLLECTOR_CONFIGURATION_ERROR = r'{prefix}.*{severity}: \(\d+\): Configuration error at \'{conf_path}\'.'
LOGCOLLECTOR_LOG_FILE_DUPLICATED = r'.*Log file (.+) is duplicated.'
LOGCOLLECTOR_MACOS_MONITORING_LOGS = r'.*Monitoring macOS logs with: {command_path} stream --style syslog'
LOGCOLLECTOR_DJB_PROGRAM_NAME = r'.*INFO: Using program name \'{program_name}\' for DJB multilog file: \'{multilog_file}\'.'
LOGCOLLECTOR_MACOS_INVALID_LOCATION = r'.*Invalid location value \'{location}\' when using \'macos\' as \'log_format\'. Default value will be used.'
LOGCOLLECTOR_MACOS_MISSING_LOCATION = r'.*Missing \'location\' element when using \'macos\' as \'log_format\'. Default value will be used.'
LOGCOLLECTOR_EVENTCHANNEL_BAD_FORMAT = r'.*ERROR: Could not EvtSubscribe\(\) for \({event_location}\) which returned \(\d+\)'
LOGCOLLECTOR_ANALYZING_EVENT_LOG = r'.*INFO: \(\d+\): Analyzing event log: \'{event_location}\''
LOGCOLLECTOR_INVALID_RECONNECTION_TIME_VALUE = r'.*{severity}: Invalid reconnection time value. Changed to {default_value} seconds.'
LOGCOLLECTOR_MODULE_START = r'.*LogCollectorStart\(\): INFO: Started \(pid: \d+\).'

ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
ERROR_CONFIGURATION = 'The expected configuration was not found in the module configuration response'
ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"
ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
ERROR_GENERIC_MESSAGE = 'The expected error output has not been produced'
ERROR_LOG_FILE_DUPLICATED = 'The expected warning log file duplicated has not been produced.'
ERROR_ANALYZING_MACOS = 'The expected analyzing macos log has not been produced'
ERROR_DJB_MULTILOG_NOT_PRODUCED = 'The expected multilog djb log has not been produced'
ERROR_INVALID_MACOS_VALUE = 'The expected warning invalid macos value has not been produced'
ERROR_MISSING_LOCATION_VALUE = 'The expected warning missing location value has not been produced'
ERROR_MACOS_LOG_NOT_PRODUCED = 'The expected macos log monitoring has not been produced'
ERROR_EVENTCHANNEL = 'Did not receive the expected "ERROR: Could not EvtSubscribe() for ... which returned ... event.'
ERROR_INVALID_RECONNECTION_TIME = 'The expected invalid reconnection time error has not been produced'
