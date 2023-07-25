# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
ANALYSISD_STARTED = fr"{PREFIX}Input message handler thread started."
ANALYSISD_ERROR_MESSAGES = r'.* (?:DEBUG|ERROR): ((?:dbsync:|No member|No such member|Invalid) .*)'
ANALYSISD_EPS_ENABLED = r".*INFO: EPS limit enabled, EPS: '{maximum}', timeframe: '{timeframe}'"
ANALYSISD_EPS_DISABLED = r".*INFO: EPS limit disabled.*"
ANALYSISD_EPS_MISSING_MAX = r".*WARNING: The EPS maximum value is missing in the configuration block.*"
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
