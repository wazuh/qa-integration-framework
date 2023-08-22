# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Callback patterns to find events in log file.
IGNORING_DUE_TO_SREGEX = r".*?Ignoring path '(.*)' due to sregex '(.*)'.*"
IGNORING_DUE_TO_PATTERN = r".*?Ignoring path '(.*)' due to pattern '(.*)'.*"
REALTIME_WHODATA_ENGINE_STARTED = r'.*File integrity monitoring real-time Whodata engine started.*'
MONITORING_PATH = r'.*Monitoring path:.*'
SENDING_FIM_EVENT =  r'.*Sending FIM event: .*"type":"event".*'
ADDED_EVENT = r'.*"type":"added".*'
DELETED_EVENT = r'.*"type":"deleted".*'
INODE_ENTRIES_PATH_COUNT =  r".*Fim inode entries: '(\d+)', path count: '(\d+)'"
WHODATA_NOT_STARTED = r'.*Who-data engine could not start. Switching who-data to real-time.'
EMPTY_DIRECTORIES_TAG = r'.*Empty directories tag found in the configuration.*'
FILE_LIMIT_PERCENTAGE = r'.*File database is (\d+)% full.'

EXTRACT_EVENT_JSON =  r'.*Sending FIM event: (.+)$'
