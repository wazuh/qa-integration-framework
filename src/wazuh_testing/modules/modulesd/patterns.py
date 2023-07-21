# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


# Callback patterns to find events in log file.
MODULESD_CONFIGURATION_ERROR = r".*ERROR: {error_type} content for tag '{tag}' at module '{integration}'."
MODULESD_STARTED = r".*INFO: Module {integration} started."
