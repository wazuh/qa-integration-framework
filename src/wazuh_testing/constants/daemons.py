# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

AGENT_DAEMON = 'wazuh-agentd'
AGENT_EXEC_DAEMON = 'wazuh-execd'
AGENT_MODULES_DAEMON = 'wazuh-modulesd'
LOGCOLLECTOR_DAEMON = 'wazuh-logcollector'
SYSCHECK_DAEMON = 'wazuh-syscheckd'

ANALYSISD_DAEMON = 'wazuh-manager-analysisd'
API_DAEMON = 'wazuh-manager-apid'
AUTHD_DAEMON = 'wazuh-manager-authd'
CLUSTER_DAEMON = 'wazuh-manager-clusterd'
MODULES_DAEMON = 'wazuh-manager-modulesd'
MONITOR_DAEMON = 'wazuh-manager-monitord'
REMOTE_DAEMON = 'wazuh-manager-remoted'
WAZUH_DB_DAEMON = 'wazuh-manager-db'

WAZUH_AGENT_DAEMONS = [AGENT_DAEMON,
                       AGENT_EXEC_DAEMON,
                       AGENT_MODULES_DAEMON,
                       LOGCOLLECTOR_DAEMON,
                       SYSCHECK_DAEMON]

WAZUH_MANAGER_DAEMONS = [ANALYSISD_DAEMON,
                         API_DAEMON,
                         CLUSTER_DAEMON,
                         MODULES_DAEMON,
                         MONITOR_DAEMON,
                         REMOTE_DAEMON,
                         WAZUH_DB_DAEMON]

API_DAEMONS_REQUIREMENTS = [API_DAEMON,
                            WAZUH_DB_DAEMON,
                            ANALYSISD_DAEMON,
                            REMOTE_DAEMON,
                            MODULES_DAEMON]

WAZUH_AGENT = 'wazuh-agent'
WAZUH_MANAGER = 'wazuh-manager'

WAZUH_AGENT_WIN = 'wazuh-agent.exe'
