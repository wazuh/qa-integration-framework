# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

BACKUP_CREATION_CALLBACK = r'.*Created Global database backup "(backup/db/global.db-backup.*.gz)"'
WRONG_INTERVAL_CALLBACK = r".*Invalid value for element ('interval':.*)"
WRONG_MAX_FILES_CALLBACK = r".*Invalid value for element ('max_files':.*)"
