# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Internal configuration options.
#
# AGENT ONLY. The agent keeps the `monitord.*` namespace for its own log rotation, read by
# wazuh-agentd. The manager's equivalent moved to `wazuh_modules.manager_task_log_*` when its
# rotation became a Task Manager job; a manager test must use those names, not these.
MONITORD_ROTATE_LOG = 'monitord.rotate_log'
