# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

AGENT_DAEMON = 'wazuh-agentd'
ANALYSISD_DAEMON = 'wazuh-analysisd'
API_DAEMON = 'wazuh-apid'
AUTHD_DAEMON = 'wazuh-authd'
CLUSTER_DAEMON = 'wazuh-clusterd'
EXEC_DAEMON = 'wazuh-execd'
MODULES_DAEMON = 'wazuh-modulesd'
MONITOR_DAEMON = 'wazuh-monitord'
LOGCOLLECTOR_DAEMON = 'wazuh-logcollector'
REMOTE_DAEMON = 'wazuh-remoted'
SYSCHECK_DAEMON = 'wazuh-syscheckd'
WAZUH_DB_DAEMON = 'wazuh-db'

WAZUH_AGENT_DAEMONS = [AGENT_DAEMON,
                       EXEC_DAEMON,
                       MODULES_DAEMON,
                       LOGCOLLECTOR_DAEMON,
                       SYSCHECK_DAEMON]

WAZUH_MANAGER_DAEMONS = [ANALYSISD_DAEMON,
                         API_DAEMON,
                         CLUSTER_DAEMON,
                         EXEC_DAEMON,
                         LOGCOLLECTOR_DAEMON,
                         MODULES_DAEMON,
                         MONITOR_DAEMON,
                         REMOTE_DAEMON,
                         SYSCHECK_DAEMON,
                         WAZUH_DB_DAEMON]

API_DAEMONS_REQUIREMENTS = [API_DAEMON,
                            WAZUH_DB_DAEMON,
                            EXEC_DAEMON,
                            ANALYSISD_DAEMON,
                            REMOTE_DAEMON,
                            MODULES_DAEMON]

WAZUH_AGENT = 'wazuh-agent'
WAZUH_MANAGER = 'wazuh-manager'

WAZUH_AGENT_WIN = 'wazuh-agent.exe'
