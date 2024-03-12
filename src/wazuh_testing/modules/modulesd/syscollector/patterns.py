# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX
from . import WMODULES_PREFIX


# Callback messages
CB_MODULE_STARTING = fr'{PREFIX}DEBUG: Starting Syscollector.'
CB_MODULE_STARTED = fr'{PREFIX}INFO: Module started.'
CB_SCAN_STARTED = fr'{PREFIX}INFO: Starting evaluation.'
CB_SCAN_FINISHED = fr'{PREFIX}INFO: Evaluation finished.'
CB_SYNC_STARTED = fr'{PREFIX}DEBUG: Starting syscollector sync'
CB_SYNC_FINISHED = fr'{PREFIX}DEBUG: Ending syscollector sync'
CB_SYSCOLLECTOR_DISABLED = fr'{PREFIX}INFO: Module disabled. Exiting...'
CB_HARDWARE_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting hardware scan'
CB_HARDWARE_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending hardware scan'
CB_OS_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting os scan'
CB_OS_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending os scan'
CB_NETWORK_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting network scan'
CB_NETWORK_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending network scan'
CB_PACKAGES_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting packages scan'
CB_PACKAGES_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending packages scan'
CB_PORTS_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting ports scan'
CB_PORTS_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending ports scan'
CB_PROCESSES_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting processes scan'
CB_PROCESSES_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending processes scan'
CB_HOTFIXES_SCAN_STARTED = fr'{PREFIX}DEBUG: Starting hotfixes scan'
CB_HOTFIXES_SCAN_FINISHED = fr'{PREFIX}DEBUG: Ending hotfixes scan'
CB_FIELDS_MAX_EPS = fr"{WMODULES_PREFIX}WARNING:.* Invalid value for element 'max_eps': .*"
CB_FIELDS_INTERVAL = fr"{WMODULES_PREFIX}ERROR: Invalid interval at module 'syscollector'"
CB_FIELDS_ALL = fr"{WMODULES_PREFIX}ERROR: Invalid content for tag '{{0}}' at module 'syscollector'."
CB_CHECK_CONFIG = fr'{PREFIX}DEBUG:.*"disabled":"no","scan-on-start":"yes",'\
    '"interval":3600,"network":"yes","os":"yes","hardware":"yes","packages":"yes",'\
    '"ports":"yes","ports_all":"no","processes":"yes","sync_max_eps":10.*'
CB_CHECK_CONFIG_WIN = fr'{PREFIX}DEBUG:.*"disabled":"no","scan-on-start":"yes",'\
    '"interval":3600,"network":"yes","os":"yes","hardware":"yes","packages":"yes",'\
    '"ports":"yes","ports_all":"no","processes":"yes","hotfixes":"yes","sync_max_eps":10.*'
