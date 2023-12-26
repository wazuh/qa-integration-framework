# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
ANALYSISD_STARTED = fr"{PREFIX}Input message handler thread started."
ANALYSISD_ERROR_MESSAGES = r'.* (?:DEBUG|ERROR): ((?:dbsync:|No member|No such member|Invalid) .*)'
ANALYSISD_EPS_ENABLED = r".*INFO: EPS limit enabled, EPS: '{maximum}', timeframe: '{timeframe}'"
ANALYSISD_EPS_DISABLED = r".*INFO: EPS limit disabled.*"
ANALYSISD_EPS_MISSING_MAX = r".*WARNING: EPS limit disabled.*"
ANALYSISD_EPS_QUEUES_FULL = r'.*{log_level}: Queues are full and no EPS credits, dropping events.*'
ANALYSISD_EPS_QUEUES_NORMAL = r'.*{log_level}: Queues back to normal and EPS credits, no dropping events.*'
ANALYSISD_CONFIGURATION_ERROR = r".* \(\d+\): Configuration error at.*"

# Callback patterns to find events in alerts file.
ANALYSISD_ALERT_STARTED = r'.*Ossec server started.*'

# Callback patterns to find events in socket.
ANALYSISD_QUEUE_DB_MESSSAGE = r"^agent (\d{3,}) \w+ (\w+) (.+)$"
ANALYSISD_SYSCHECK_MESSSAGE = r'(.*)syscheck:(.+)$'

# Alerts useful IDs
ANALYSISD_ALERTS_SYSCHECK_IDS = ['550', '553', '554', '594', '597', '598', '750', '751', '752']

# Logtest patterns
LOGTEST_STARTED = fr'{PREFIX}.*INFO: \(\d+\): Logtest started'
LOGTEST_DISABLED = fr'{PREFIX}.*INFO: \(\d+\): Logtest disabled'
LOGTEST_CONFIG_ERROR = fr'{PREFIX}.*ERROR: \(\d+\): Invalid value for element'
LOGTEST_SESSION_INIT = r".*\(7202\): Session initialized with token '(\w{8})'"
LOGTEST_REMOVE_SESSION = r".*\(7206\): The session '(\w{8})' was closed successfully"
LOGTEST_INVALID_TOKEN = r".*\(7309\): '(\S+)' is not a valid token"
