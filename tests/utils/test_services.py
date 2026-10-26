# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Unit tests for the daemon process matching of wazuh_testing.utils.services.control_service."""

import os
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from wazuh_testing.utils import services


@patch('wazuh_testing.utils.services.sys.platform', 'linux')
@patch('wazuh_testing.utils.services.psutil.process_iter')
@patch('wazuh_testing.utils.services.psutil.wait_procs')
@patch('wazuh_testing.utils.services.sockets.delete_sockets')
def test_control_service_stop_daemon_by_name(mock_delete_sockets, mock_wait_procs, mock_process_iter):
    """Test control_service stops a process whose name is the daemon."""
    mock_proc = MagicMock()
    mock_proc.name.return_value = 'wazuh-agentd'
    mock_proc.cmdline.return_value = ['wazuh-agentd']
    mock_process_iter.return_value = [mock_proc]
    mock_wait_procs.return_value = ([], [])
    services.control_service('stop', daemon='wazuh-agentd')

    mock_proc.terminate.assert_called_once()


@patch('wazuh_testing.utils.services.sys.platform', 'linux')
@patch('wazuh_testing.utils.services.psutil.process_iter')
@patch('wazuh_testing.utils.services.psutil.wait_procs')
@patch('wazuh_testing.utils.services.sockets.delete_sockets')
def test_control_service_stop_daemon_matches_binary_path(mock_delete_sockets, mock_wait_procs, mock_process_iter):
    """Test control_service stops a daemon launched by absolute path with arguments."""
    mock_proc = MagicMock()
    mock_proc.name.return_value = 'wazuh-logcollec'  # comm truncated to 15 chars by the kernel
    mock_proc.cmdline.return_value = ['/var/ossec/bin/wazuh-logcollector', '-dd']
    mock_process_iter.return_value = [mock_proc]
    mock_wait_procs.return_value = ([], [])
    services.control_service('stop', daemon='wazuh-logcollector')

    mock_proc.terminate.assert_called_once()


@patch('wazuh_testing.utils.services.sys.platform', 'linux')
@patch('wazuh_testing.utils.services.psutil.process_iter')
@patch('wazuh_testing.utils.services.psutil.wait_procs')
@patch('wazuh_testing.utils.services.sockets.delete_sockets')
@pytest.mark.parametrize('cmdline', [
    ['sudo', 'GITHUB_REF_NAME=fix/1-wazuh-agentd-exits-1', 'python', '-m', 'pytest'],
    ['grep', 'wazuh-agentd'],
    ['tail', '-f', '/var/ossec/logs/wazuh-agentd.log'],
    ['wazuh-agentd-wrapper'],
])
def test_control_service_stop_daemon_ignores_processes_mentioning_it(mock_delete_sockets, mock_wait_procs,
                                                                     mock_process_iter, cmdline):
    """Test control_service does not signal processes whose command line only mentions the daemon."""
    mock_proc = MagicMock()
    mock_proc.name.return_value = cmdline[0]
    mock_proc.cmdline.return_value = cmdline
    mock_process_iter.return_value = [mock_proc]
    mock_wait_procs.return_value = ([], [])
    services.control_service('stop', daemon='wazuh-agentd')

    mock_proc.terminate.assert_not_called()
    mock_proc.kill.assert_not_called()


@patch('wazuh_testing.utils.services.sys.platform', 'linux')
@patch('wazuh_testing.utils.services.psutil.process_iter')
@patch('wazuh_testing.utils.services.psutil.wait_procs')
@patch('wazuh_testing.utils.services.sockets.delete_sockets')
def test_control_service_stop_daemon_never_signals_own_ancestors(mock_delete_sockets, mock_wait_procs,
                                                                 mock_process_iter):
    """Test control_service never signals the current process or its ancestors, even if they match."""
    mock_self = MagicMock(pid=os.getpid())
    mock_parent = MagicMock(pid=os.getppid())
    for mock_proc in (mock_self, mock_parent):
        mock_proc.name.return_value = 'wazuh-agentd'
        mock_proc.cmdline.return_value = ['wazuh-agentd']
    mock_process_iter.return_value = [mock_self, mock_parent]
    mock_wait_procs.return_value = ([], [])
    services.control_service('stop', daemon='wazuh-agentd')

    mock_self.terminate.assert_not_called()
    mock_parent.terminate.assert_not_called()


@patch('wazuh_testing.utils.services.sys.platform', 'linux')
@patch('wazuh_testing.utils.services.sockets.delete_sockets')
def test_control_service_stop_daemon_spares_real_decoy_process(mock_delete_sockets):
    """Test control_service leaves alive a real process whose arguments contain the daemon name."""
    decoy = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', 'wazuh-agentd'])
    try:
        time.sleep(0.2)
        services.control_service('stop', daemon='wazuh-agentd')

        assert decoy.poll() is None
    finally:
        decoy.kill()
        decoy.wait()
