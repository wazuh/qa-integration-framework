# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import json
from . import PREFIX


# Callback Messages
CB_SCA_ENABLED = fr"{PREFIX}INFO: (Module started.)"
CB_SCA_DISABLED = fr"{PREFIX}INFO: (Module disabled). Exiting."
CB_SCA_SCAN_STARTED = fr"{PREFIX}INFO: (Starting Security Configuration Assessment scan)."
CB_SCA_SCAN_ENDED = fr"{PREFIX}INFO: Security Configuration Assessment scan finished. Duration: (\d+) seconds."
CB_SCA_OSREGEX_ENGINE = fr"{PREFIX}DEBUG: SCA will use '(.*)' engine to check the rules."
CB_POLICY_EVALUATION_FINISHED = fr"{PREFIX}INFO: Evaluation finished for policy '(.*)'."
CB_SCAN_DB_DUMP_FINISHED = fr"{PREFIX}DEBUG: Finished dumping scan results to SCA DB for policy '(.*)'.*"
CB_SCAN_RULE_RESULT = fr"{PREFIX}wm_sca_hash_integrity.*DEBUG: ID: (\d+); Result: '(.*)'"
CB_SCA_SCAN_EVENT = r".*sca_send_alert.*Sending event: (.*)"


# Error Messages
ERR_MSG_REGEX_ENGINE = "Did not receive the expected 'SCA will use '.*' engine to check the rules' event"
ERR_MSG_ID_RESULTS = 'Expected sca_has_integrity result events not found'
ERR_MSG_SCA_SUMMARY = 'Expected SCA Scan Summary type event not found.'


# Callback functions
def callback_scan_id_result(line):
    '''Callback that returns the ID an result of a SCA check
    Args:
        line (str): line string to check for match.
    '''
    match = re.match(CB_SCAN_RULE_RESULT, line)
    if match:
        return [match.group(1), match.group(2)]


def callback_detect_sca_scan_summary(line):
    '''Callback that return the json from a SCA summary event.
    Args:
        line (str): line string to check for match.
    '''
    match = re.match(CB_SCA_SCAN_EVENT, line)
    if match:
        if json.loads(match.group(1))['type'] == 'summary':
            return json.loads(match.group(1))


# Variables
TEMP_FILE_PATH = '/tmp'