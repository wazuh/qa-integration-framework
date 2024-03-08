# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
INTEGRATORD_CONNECTED = "JSON file queue connected."
INTEGRATORD_THIRD_PARTY_RESPONSE = r'.*<Response \[.*\]>'
INTEGRATORD_INODE_CHANGED = r'.*DEBUG: jqueue_next.*Alert file inode changed.*'
INTEGRATORD_INVALID_ALERT_READ = r'.*WARNING: Invalid JSON alert read.*'
INTEGRATORD_OVERLONG_ALERT_READ = r'.*WARNING: Overlong JSON alert read.*'
