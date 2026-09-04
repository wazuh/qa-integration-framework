# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import WAZUH_DB_PREFIX


BACKUP_CREATION_CALLBACK = r'.*Created Global database backup "(backup/db/global.db-backup.*.gz)"'
# etc/wazuh-manager.yml is validated against its schema: an invalid backup option is reported with the
# JSON pointer of the offending value (1244) before wazuh-db starts.
WRONG_INTERVAL_CALLBACK = r".*\(1244\): Invalid configuration at .*/wdb/backup/global/interval.*"
WRONG_MAX_FILES_CALLBACK = r".*\(1244\): Invalid configuration at .*/wdb/backup/global/max_files.*"
