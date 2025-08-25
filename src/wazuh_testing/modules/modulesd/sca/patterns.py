# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX

# Callback Messages
SCA_ENABLED = fr"{PREFIX}INFO: SCA module enabled"
SCA_DISABLED = fr"{PREFIX}INFO: SCA module disabled\. Exiting"
SCA_STARTING = fr"{PREFIX}INFO: Starting SCA module"
SCA_RUNNING = fr"{PREFIX}INFO: SCA module running"
SCA_SCAN_STARTED_REQ = fr"{PREFIX}DEBUG: Starting Policy requirements evaluation for policy \"(.*?)\""
SCA_SCAN_ENDED_REQ = fr"{PREFIX}DEBUG: Policy requirements evaluation completed for policy \"(.*?)\", result: (Passed|Failed)"
SCA_SCAN_STARTED_CHECK = fr"{PREFIX}DEBUG: Starting Policy checks evaluation for policy \"(.*?)\""
SCA_SCAN_RESULT = fr"{PREFIX}DEBUG: Policy check \"(\d+)\" evaluation completed for policy \"(.*?)\", result: (Passed|Failed)"
SCA_SCAN_ENDED_CHECK = fr"{PREFIX}DEBUG: Policy checks evaluation completed for policy \"(.*?)\""