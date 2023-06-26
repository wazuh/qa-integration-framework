# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
EXECD_THREAD_STARTED = fr"{PREFIX}Input message handler thread started."
EXECD_RECEIVED_MESSAGE = r'.*DEBUG: Received message.*'
EXECD_EXECUTING_COMMAND = r'.*DEBUG: Executing command.*'
