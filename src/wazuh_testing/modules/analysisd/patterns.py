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

# General fields
ALERTS_ID = 'id'
ALERTS_RULE = 'rule'
ALERTS_FULL_LOG = 'full_log'

# FIM fields
ALERTS_SYSCHECK = 'syscheck'
ALERTS_SYSCHECK_DIFF = 'diff'
ALERTS_SYSCHECK_EVENT = 'event'

# FIM events
SYSCHECK_DATA = 'data'
SYSCHECK_PATH = 'path'
SYSCHECK_INDEX = 'index'
SYSCHECK_MODE = 'mode'
SYSCHECK_TYPE = 'type'
SYSCHECK_TYPE_ADDED = 'added'
SYSCHECK_TYPE_MODIFIED = 'modified'
SYSCHECK_TYPE_DELETED = 'deleted'
SYSCHECK_ARCH = 'arch'
SYSCHECK_TIMESTAMP = 'timestamp'
SYSCHECK_ATTRIBUTES = 'attributes'
SYSCHECK_ATTRIBUTES_TYPE = 'type'
SYSCHECK_ATTRIBUTES_TYPE_FILE = 'file'
SYSCHECK_ATTRIBUTES_TYPE_REGISTRY = 'registry_key'
SYSCHECK_ATTRIBUTES_SIZE = 'size'
SYSCHECK_ATTRIBUTES_PERM = 'perm'
SYSCHECK_ATTRIBUTES_UID = 'uid'
SYSCHECK_ATTRIBUTES_GID = 'gid'
SYSCHECK_ATTRIBUTES_USER_NAME = 'user_name'
SYSCHECK_ATTRIBUTES_GROUP_NAME = 'group_name'
SYSCHECK_ATTRIBUTES_INODE = 'inode'
SYSCHECK_ATTRIBUTES_MTIME = 'mtime'
SYSCHECK_ATTRIBUTES_HASH = 'hash'
SYSCHECK_ATTRIBUTES_CHECKSUM = 'checksum'
SYSCHECK_OLD_ATTRIBUTES = 'old_attributes'
SYSCHECK_CHANGED_ATTRIBUTES = 'changed_attributes'
SYSCHECK_VALUE_NAME = 'value_name'
SYSCHECK_VALUE_TYPE = 'value_type'
SYSCHECK_CONTENT_CHANGES = 'content_changes'
SYSCHECK_TAGS = 'tags'
