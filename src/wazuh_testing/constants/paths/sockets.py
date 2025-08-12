# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from . import WAZUH_PATH


QUEUE_CLUSTER_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
QUEUE_SOCKETS_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets')
QUEUE_AGENTS_TIMESTAMP_PATH = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')
QUEUE_DIFF_PATH = os.path.join(WAZUH_PATH, 'queue', 'diff')
QUEUE_RIDS_PATH = os.path.join(WAZUH_PATH, 'queue', 'rids')
QUEUE_ALERTS_PATH = os.path.join(WAZUH_PATH, 'queue', 'alerts')
DIFF_PATH_FILE = os.path.join(QUEUE_DIFF_PATH, 'file')

ANALYSISD_ANALISIS_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'analysis')
ANALYSISD_QUEUE_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'queue')
AUTHD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'auth')
EXECD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'com')
LOGCOLLECTOR_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logcollector')
LOGTEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logtest')
MODULESD_WMODULES_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wmodules')
MODULESD_DOWNLOAD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'download')
MODULESD_CONTROL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'control')
MODULESD_KREQUEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'krequest')
MODULESD_C_INTERNAL_SOCKET_PATH = os.path.join(QUEUE_CLUSTER_PATH, 'c-internal.sock')
MONITORD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'monitor')
REMOTED_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'remote')
SYSCHECKD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'syscheck')
WAZUH_DB_SOCKET_PATH = os.path.join(QUEUE_DB_PATH, 'wdb')
ACTIVE_RESPONSE_SOCKET_PATH = os.path.join(QUEUE_ALERTS_PATH, 'ar')


WAZUH_SOCKETS = {
    'wazuh-agentd': [],
    'wazuh-apid': [],
    'wazuh-agentlessd': [],
    'wazuh-csyslogd': [],
    'wazuh-integratord': [],
    'wazuh-analysisd': [
        ANALYSISD_ANALISIS_SOCKET_PATH,
        ANALYSISD_QUEUE_SOCKET_PATH
    ],
    'wazuh-authd': [AUTHD_SOCKET_PATH],
    'wazuh-execd': [EXECD_SOCKET_PATH],
    'wazuh-logcollector': [LOGCOLLECTOR_SOCKET_PATH],
    'wazuh-monitord': [MONITORD_SOCKET_PATH],
    'wazuh-remoted': [REMOTED_SOCKET_PATH],
    'wazuh-maild': [],
    'wazuh-syscheckd': [SYSCHECKD_SOCKET_PATH],
    'wazuh-db': [WAZUH_DB_SOCKET_PATH],
    'wazuh-modulesd': [
        MODULESD_WMODULES_SOCKET_PATH,
        MODULESD_DOWNLOAD_SOCKET_PATH,
        MODULESD_CONTROL_SOCKET_PATH,
        MODULESD_KREQUEST_SOCKET_PATH
    ],
    'wazuh-clusterd': [MODULESD_C_INTERNAL_SOCKET_PATH]
}

# These sockets do not exist with default Wazuh configuration
WAZUH_OPTIONAL_SOCKETS = [
    MODULESD_KREQUEST_SOCKET_PATH,
    AUTHD_SOCKET_PATH
]
