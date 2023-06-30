# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
SID_NOT_FOUND = r".*Signature ID '(\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\d*)'"
EMPTY_IF_SID_RULE_IGNORED = fr"{PREFIX}Empty 'if_sid' value. Rule '(\d*)' will be ignored.*"
INVALID_IF_SID_RULE_IGNORED = fr"{PREFIX}Invalid 'if_sid' value: '(.*)'. Rule '(\d*)' will be ignored.*"
INVALID_EMPTY_IF_SID_RULE_IGNORED = fr"{PREFIX}Invalid 'if_sid' value: ''. Rule '(\d*)' will be ignored.*"
