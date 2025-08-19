# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from . import WAZUH_PATH


CVE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'vulnerabilities', 'cve.db')
CPE_HELPER_PATH = os.path.join(WAZUH_PATH, 'queue', 'vulnerabilities', 'dictionaries', 'cpe_helper.json')

FIM_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'fim', 'db', 'fim.db')

FIM_SYNC_DB_DIR = os.path.join(WAZUH_PATH, 'queue', 'fim', 'db')
FIM_SYNC_DB_FILES = [
    'fim_sync.db',
    'fim_sync.db-shm',
    'fim_sync.db-wal'
]
