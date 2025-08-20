# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
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

# New Callback Messages
NCB_SCA_ENABLED = fr"{PREFIX}INFO: SCA module enabled."
NCB_SCA_DISABLED = fr"{PREFIX}INFO: SCA module disabled. Exiting."
NCB_SCA_STARTING = fr"{PREFIX}INFO: Starting SCA module..."
NCB_SCA_RUNNING = fr"{PREFIX}INFO: SCA module running."
NCB_SCA_SCAN_STARTED_REQ = fr"{PREFIX}DEBUG: Starting Policy requirements evaluation for policy *"
NCB_SCA_SCAN_ENDED_REQ = fr"{PREFIX}DEBUG: Policy requirements evaluation completed for policy *"
NCB_SCA_SCAN_STARTED_CHECK = fr"{PREFIX}DEBUG: Starting Policy checks evaluation for policy *"
NCB_SCA_SCAN_RESULT = fr"{PREFIX}DEBUG: Policy check \"(\d+)\" evaluation completed for policy \"(.*)\", result: (.*)."
NCB_SCA_SCAN_ENDED_CHECK = fr"{PREFIX}DEBUG: Policy checks evaluation completed for policy *"