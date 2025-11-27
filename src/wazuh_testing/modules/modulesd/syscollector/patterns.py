# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from . import PREFIX, WMODULES_PREFIX

# Callback messages
CB_MODULE_STARTING = rf"{PREFIX}DEBUG: Starting Syscollector."
CB_MODULE_STARTED = rf"{PREFIX}INFO: Module started."
CB_SCAN_STARTED = rf"{PREFIX}INFO: Starting evaluation."
CB_SCAN_FINISHED = rf"{PREFIX}INFO: Evaluation finished."
CB_SYSCOLLECTOR_DISABLED = rf"{PREFIX}INFO: Module disabled. Exiting..."
CB_HARDWARE_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting hardware scan"
CB_HARDWARE_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending hardware scan"
CB_OS_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting os scan"
CB_OS_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending os scan"
CB_NETWORK_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting network scan"
CB_NETWORK_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending network scan"
CB_PACKAGES_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting packages scan"
CB_PACKAGES_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending packages scan"
CB_PORTS_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting ports scan"
CB_PORTS_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending ports scan"
CB_PROCESSES_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting processes scan"
CB_PROCESSES_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending processes scan"
CB_HOTFIXES_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting hotfixes scan"
CB_HOTFIXES_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending hotfixes scan"
CB_GROUPS_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting groups scan"
CB_GROUPS_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending groups scan"
CB_USERS_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting users scan"
CB_USERS_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending users scan"
CB_SERVICES_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting services scan"
CB_SERVICES_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending services scan"
CB_BROWSER_EXTENSIONS_SCAN_STARTED = rf"{PREFIX}DEBUG: Starting browser extensions scan"
CB_BROWSER_EXTENSIONS_SCAN_FINISHED = rf"{PREFIX}DEBUG: Ending browser extensions scan"
CB_FIELDS_MAX_EPS = (
    rf"{WMODULES_PREFIX}WARNING:.* Invalid value for element 'max_eps': .*"
)
CB_FIELDS_INTERVAL = (
    rf"{WMODULES_PREFIX}ERROR: Invalid interval at module 'syscollector'"
)
CB_FIELDS_ALL = rf"{WMODULES_PREFIX}ERROR: Invalid content for tag '{{0}}' at module 'syscollector'."
CB_CHECK_CONFIG = (
    rf'{PREFIX}DEBUG:.*"disabled":"no","scan-on-start":"yes",'
    '"interval":3600,"max_eps":50,"notify_first_scan":"no","network":"yes","os":"yes"'
    ',"hardware":"yes","packages":"yes","ports":"yes","ports_all":"no","processes":"yes"'
    ',"groups":"yes","users":"yes","services":"yes","browser_extensions":"yes".*'
)
CB_CHECK_CONFIG_WIN = (
    rf'{PREFIX}DEBUG:.*"disabled":"no","scan-on-start":"yes",'
    '"interval":3600,"max_eps":50,"notify_first_scan":"no","network":"yes","os":"yes"'
    ',"hardware":"yes","packages":"yes","ports":"yes","ports_all":"no","processes":"yes"'
    ',"groups":"yes","users":"yes","services":"yes","browser_extensions":"yes","hotfixes":"yes".*'
)

# DataClean on collector disable patterns
CB_ALL_DISABLED_COLLECTORS_EXIT = (
    rf"{PREFIX}INFO: All collectors are disabled. Exiting..."
)
CB_DISABLED_COLLECTORS_DETECTED = (
    rf"{PREFIX}INFO: Disabled collectors indices with data detected: .*"
)
CB_DATACLEAN_NOTIFICATION_STARTED = (
    rf"{PREFIX}INFO: Notifying DataClean for disabled collectors indices: .*"
)
