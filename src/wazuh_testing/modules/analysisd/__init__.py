# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

PREFIX = r'.*wazuh-analysisd.*'

QUEUE_EVENTS_SIZE = 16384
ONE_THREAD_CONFIG = {'analysisd.event_threads': '1', 'analysisd.syscheck_threads': '1',
                     'analysisd.syscollector_threads': '1', 'analysisd.rootcheck_threads': '1',
                     'analysisd.sca_threads': '1', 'analysisd.hostinfo_threads': '1',
                     'analysisd.winevt_threads': '1', 'analysisd.rule_matching_threads': '1',
                     'analysisd.dbsync_threads': '1', 'remoted.worker_pool': '1'}
