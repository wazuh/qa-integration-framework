# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Callback patterns to find events in log file.
IGNORING_DUE_TO_SREGEX = r".*?Ignoring path '(.*)' due to sregex '(.*)'.*"
IGNORING_DUE_TO_PATTERN = r".*?Ignoring path '(.*)' due to pattern '(.*)'.*"
REALTIME_WHODATA_ENGINE_STARTED = r'.*File integrity monitoring real-time Whodata engine started.*'
MONITORING_PATH = r'.*Monitoring path:.*'

NUM_INOTIFY_WATCHES = r'.*Folders monitored with real-time engine: (\d+)'
PATH_MONITORED_REALTIME = r".*Directory added for real time monitoring: (.*)"
PATH_MONITORED_WHODATA = r".*Added audit rule for monitoring directory: (.*)"
PATH_MONITORED_WHODATA_WINDOWS = r".*Setting up SACL for (.*)"

# Events
SENDING_FIM_EVENT = r'.*Sending FIM event: .*"type":"event".*'
EVENT_TYPE_ADDED = r'.*Sending FIM event: .*"type":"added".*'
EVENT_TYPE_MODIFIED = r'.*Sending FIM event: .*"type":"modified".*'
EVENT_TYPE_DELETED = r'.*Sending FIM event: .*"type":"deleted".*'
FIM_EVENT_JSON = r'.*Sending FIM event: (.+)$'

INODE_ENTRIES_PATH_COUNT = r".*Fim inode entries: '(\d+)', path count: '(\d+)'"
WHODATA_NOT_STARTED = r'.*Who-data engine could not start. Switching who-data to real-time.'
EMPTY_DIRECTORIES_TAG = r'.*Empty directories tag found in the configuration.*'

FILE_LIMIT_PERCENTAGE = r'.*File database is (\d+)% full.'
FILE_LIMIT_DISABLED = r'.*No limit set to maximum number of file entries to be monitored'
FILE_LIMIT_AMOUNT = r".*Maximum number of files to be monitored: '(\d+)'"

FILE_LIMIT_PERCENTAGE = r'.*File database is (\d+)% full.'
FILE_LIMIT_DISABLED = r'.*No limit set to maximum number of file entries to be monitored'
FILE_LIMIT_AMOUNT = r".*Maximum number of files to be monitored: '(\d+)'"

LINKS_SCAN_FINALIZED = r'.*Links check finalized.*'
AUDIT_RULES_RELOADED = r'.*Audit rules reloaded\. Rules loaded: (.+)'
EXTRACT_FIM_EVENT_JSON =  r'.*Sending FIM event: (.+)$'
