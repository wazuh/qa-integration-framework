# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX


# Callback patterns to find events in log file.
ANALYSISD_STARTED = fr"{PREFIX}Input message handler thread started."
ANALYSISD_ERROR_MESSAGES = r'.* (?:DEBUG|ERROR): ((?:dbsync:|No member|No such member|Invalid) .*)'

# Callback patterns to find events in alerts file.
ANALYSISD_ALERT_STARTED = r'.*Ossec server started.*'

# Callback patterns to find events in socket.
ANALYSISD_QUEUE_DB_MESSSAGE = r"^agent (\d{3,}) \w+ (\w+) (.+)$"
ANALYSISD_SYSCHECK_MESSSAGE = r'(.*)syscheck:(.+)$'

# Alerts useful IDs
ANALYSISD_ALERTS_SYSCHECK_IDS = ['550', '553', '554', '594', '597', '598', '750', '751', '752']
