# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

PREFIX = r'.*wazuh-analysisd.*'

QUEUE_EVENTS_SIZE = 16384
ANALYSISD_DEBUG_CONFIG = {'analysisd.debug': '2', 'monitord.rotate_log': '0'}
ANALYSISD_DAEMON_HANDLER = {'daemons': ['wazuh-analysisd']}
