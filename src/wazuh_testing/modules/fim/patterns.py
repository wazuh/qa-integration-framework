# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Callback patterns to find events in log file.
IGNORING_DUE_TO_SREGEX = r".*?Ignoring path '(.*)' due to sregex '(.*)'.*"
IGNORING_DUE_TO_PATTERN = r".*?Ignoring path '(.*)' due to pattern '(.*)'.*"
REALTIME_WHODATA_ENGINE_STARTED = r'.*File integrity monitoring real-time Whodata engine started.'
SENDING_FIM_EVENT =  r'.*Sending FIM event:.*'
WHODATA_ADDED_EVENT = fr"{SENDING_FIM_EVENT}added.*"
WHODATA_DELETED_EVENT = fr"{SENDING_FIM_EVENT}deleted.*"
WHODATA_NOT_STARTED = r'.*Who-data engine could not start. Switching who-data to real-time.'
