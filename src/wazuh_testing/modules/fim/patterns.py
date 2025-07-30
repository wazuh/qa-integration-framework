# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Callback patterns to find events in log file.
IGNORING_DUE_TO_SREGEX = r".*?Ignoring path '(.*)' due to sregex '(.*)'.*"
IGNORING_DUE_TO_PATTERN = r".*?Ignoring path '(.*)' due to pattern '(.*)'.*"
IGNORING_DUE_TO_RESTRICTION = r".*Ignoring entry '(.*?)' due to restriction '.*?'"
REALTIME_WHODATA_ENGINE_STARTED = r'.*File integrity monitoring real-time Whodata engine started.*'
MONITORING_PATH = r'.*Monitoring path:.*'
IGNORING_DUE_TO_INVALID_NAME = r".*Ignoring file '(.*)' due to unsupported name.*"

NUM_INOTIFY_WATCHES = r'.*Folders monitored with real-time engine: (\d+)'
PATH_MONITORED_REALTIME = r".*Directory added for real time monitoring: (.*)"
PATH_MONITORED_WHODATA = r".*Added audit rule for monitoring directory: (.*)"
PATH_MONITORED_WHODATA_WINDOWS = r".*Setting up SACL for (.*)"

# Events
EVENT_TYPE_ADDED = r'.*Sending FIM event: .*"type":"added".*'
EVENT_TYPE_MODIFIED = r'.*Sending FIM event: .*"type":"modified".*'
EVENT_TYPE_REPORT_CHANGES = r".*Sending FIM event: .*\"content_changes\":\"([^\"]*)\".*"
EVENT_UNABLE_DIFF = r".*Sending FIM event: .*\"content_changes\":\"(Unable to calculate diff due to [^\"]* limit has been reached.)\".*"
EVENT_TYPE_DELETED = r'.*Sending FIM event: .*"type":"deleted".*'
FIM_EVENT_JSON = r'.*Sending FIM event: (.+)$'
FIM_EVENT_RESTRICT = r".*Ignoring entry '(.*?)' due to restriction '.*?'"

# Scans
FIM_SCAN_START = r'.*File integrity monitoring scan started.*'
FIM_SCAN_END = r'.*File integrity monitoring scan ended.*'

INODE_ENTRIES_PATH_COUNT = r".*Fim inode entries: '(\d+)', path count: '(\d+)'"
FILE_ENTRIES_PATH_COUNT = r".*Fim file entries count: '(\d+)'"
WHODATA_NOT_STARTED = r'.*Who-data engine could not start. Switching who-data to real-time.'
EMPTY_DIRECTORIES_TAG = r'.*Empty directories tag found in the configuration.*'

FILE_LIMIT_PERCENTAGE = r'.*File database is (\d+)% full.'
FILE_LIMIT_DISABLED = r'.*No limit set to maximum number of file entries to be monitored'
FILE_LIMIT_AMOUNT = r".*Maximum number of files to be monitored: '(\d+)'"

LINKS_SCAN_FINALIZED = r'.*Links check finalized.*'
AUDIT_RULES_RELOADED = r'.*Audit rules reloaded\. Rules loaded: (.+)'

WIN_CONVERT_FOLDER = r".*fim_adjust_path.*Convert '(.*) to '(.*)' to process the FIM events."

DIFF_MAXIMUM_FILE_SIZE = r".*Maximum file size limit to generate diff information configured to \'(\d+) KB\'.*"
DIFF_DISK_QUOTA_LIMIT = r'.*Maximum disk quota size limit configured to \'(\d+) KB\'.*'
DISK_QUOTA_LIMIT_REACHED = r'.*The (.*) of the file size \'(.*)\' exceeds the disk_quota.*'
FILE_SIZE_LIMIT_REACHED = r'.*File \'(.*)\' is too big for configured maximum size to perform diff operation\.'
DIFF_FOLDER_DELETED = r'.*Folder \'(.*)\' has been deleted.*'

ERROR_MSG_MAXIMUM_FILE_SIZE_EVENT = 'Did not receive expected "Maximum file size limit configured to \'... KB\'..." event'
ERROR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE = 'Wrong value for diff_size_limit'
ERROR_MSG_DISK_QUOTA_LIMIT = 'Did not receive "Maximum disk quota size limit configured to \'... KB\'." event'
ERROR_MSG_FIM_EVENT_NOT_DETECTED = 'Did not receive expected "Sending FIM event: ..." event.'
ERROR_MSG_FILE_LIMIT_REACHED = 'Did not receive "File ... is too big ... to perform diff operation" event.'
ERROR_MSG_REPORT_CHANGES_EVENT_NOT_DETECTED = 'Did not receive event with \'content_changes\' field.'
ERROR_MSG_FOLDER_DELETED = 'Did not receive expected "Folder ... has been deleted." event.'
