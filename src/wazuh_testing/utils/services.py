# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import platform
import psutil
import re
import subprocess
import sys
import time
from typing import Tuple, Union

from wazuh_testing.constants.daemons import AGENT_MODULES_DAEMON, CLUSTER_DAEMON, API_DAEMON, WAZUH_AGENT, WAZUH_MANAGER, WAZUH_AGENT_WIN
from wazuh_testing.constants.paths.binaries import BIN_PATH, WAZUH_CONTROL_PATH
from wazuh_testing.constants.paths.sockets import WAZUH_SOCKETS, WAZUH_OPTIONAL_SOCKETS
from wazuh_testing.constants.paths.variables import VAR_RUN_PATH, VERSION_FILE
from wazuh_testing.constants.platforms import MACOS, WINDOWS

from . import sockets


def get_service() -> str:
    """
    Retrieves the name of the Wazuh service running on the current platform.

    Returns:
        str: The name of the Wazuh service. It can be either 'wazuh-manager'
             or 'wazuh-agent'.

    Raises:
        subprocess.CalledProcessError: If an error occurs while executing the
                                       subprocess to obtain the service name.

    """
    if platform.system() in ['Windows', WINDOWS]:
        return WAZUH_AGENT

    else:  # Linux, darwin...
        service = subprocess.check_output([
            WAZUH_CONTROL_PATH, "info", "-t"
        ], stderr=subprocess.PIPE).decode('utf-8').strip()

    return WAZUH_MANAGER if service in ('server', 'manager') else WAZUH_AGENT


def get_version() -> str:
    """
    Retrieves the version of the Wazuh software installed on the current platform.

    Returns:
        str: The version of the Wazuh software.

    Raises:
        FileNotFoundError: If the VERSION file cannot be found on Windows.
        subprocess.CalledProcessError: If an error occurs while executing the
                                       subprocess to obtain the version.
    """

    if platform.system() in ['Windows', WINDOWS]:
        with open(VERSION_FILE, 'r') as f:
            data = json.load(f)
            version = data.get("version", "")
            return f"v{version}"

    else:  # Linux, darwin...
        return subprocess.check_output([
            WAZUH_CONTROL_PATH, "info", "-v"
        ], stderr=subprocess.PIPE).decode('utf-8').rstrip()


def control_service(action, daemon=None, debug_mode=False):
    """Perform the stop, start and restart operation with Wazuh.

    It takes care of the current OS to interact with the service and the type of installation (agent or manager).

    Args:
        action ({'stop', 'start', 'restart'}): Action to be done with the service/daemon.
        daemon (str, optional): Name of the daemon to be controlled. None for the whole Wazuh service. Default `None`.
        debug_mode (bool, optional) : Run the specified daemon in debug mode. Default `False`.
    Raises:
        ValueError: If `action` is not contained in {'start', 'stop', 'restart'}.
        ValueError: If the result is not equal to 0.
    """
    valid_actions = ('start', 'stop', 'restart')
    if action not in valid_actions:
        raise ValueError(f'action {action} is not one of {valid_actions}')

    if sys.platform == WINDOWS:
        if action == 'restart':
            control_service('stop')
            control_service('start')
            result = 0
        else:
            error_windows_retry = 5
            retry_sleep_seconds = 10
            for attempt in range(error_windows_retry):
                command = subprocess.run(["net", action, "WazuhSvc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result = command.returncode
                if result == 0:
                    break
                else:
                    output = f"{command.stdout.decode(errors='ignore')}\n{command.stderr.decode(errors='ignore')}"
                    normalized_output = output.lower()
                    if 'service is starting or stopping' in normalized_output:
                        print(f"[control_service] Attempt {attempt+1}/{error_windows_retry}: The service is in transition. Waiting...")
                        diag = subprocess.run(["sc", "query", "WazuhSvc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print(diag.stdout.decode(errors='ignore'))
                        time.sleep(retry_sleep_seconds)
                        continue
                    if action == 'stop' and 'service is not started' in normalized_output:
                        result = 0
                        break
                    if action == 'start' and 'service has already been started' in normalized_output:
                        result = 0
                        break
                    else:
                        print(f"Unexpected error when control_service failed with the following output: {output}")
                        time.sleep(retry_sleep_seconds)
                        continue
            # If it still fails, try to force kill the process
            if result != 0:
                print("[control_service] Forcing kill of WazuhSvc.exe after failed retries...")
                for proc in psutil.process_iter(attrs=['pid', 'name']):
                    if proc.info['name'] and 'WazuhSvc' in proc.info['name']:
                        try:
                            proc.kill()
                            print(f"[control_service] Process {proc.info['name']} (PID {proc.info['pid']}) terminated.")
                        except Exception as e:
                            print(f"[control_service] Error terminating process: {e}")
                # Let SCM settle the process state before retrying net action.
                time.sleep(3)
                # Try the command again
                command = subprocess.run(["net", action, "WazuhSvc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result = command.returncode
                if result != 0:
                    print("[control_service] The service is still not responding after forced kill.")
    else:  # Default Unix
        if daemon is None:
            if sys.platform == MACOS:
                result = subprocess.run(
                    [WAZUH_CONTROL_PATH, action]).returncode
            else:
                result = subprocess.run(
                    ['service', get_service(), action]).returncode
            action == 'stop' and sockets.delete_sockets()
        else:
            if action == 'restart':
                control_service('stop', daemon=daemon)
                control_service('start', daemon=daemon)
            elif action == 'stop':
                processes = []

                for proc in psutil.process_iter():
                    try:
                        if daemon in [CLUSTER_DAEMON, API_DAEMON]:
                            for file in os.listdir(VAR_RUN_PATH):
                                if daemon in file:
                                    pid = file.split("-")
                                    pid = pid[2][0:-4]
                                    if pid == str(proc.pid):
                                        processes.append(proc)
                        elif daemon in proc.name() or daemon in ' '.join(proc.cmdline()):
                            processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                try:
                    for proc in processes:
                        proc.terminate()

                    _, alive = psutil.wait_procs(processes, timeout=5)

                    for proc in alive:
                        proc.kill()
                except psutil.NoSuchProcess:
                    pass

                sockets.delete_sockets(WAZUH_SOCKETS[daemon])
            else:
                daemon_path = BIN_PATH
                start_process = [
                    f'{daemon_path}/{daemon}'] if not debug_mode else [f'{daemon_path}/{daemon}', '-dd']
                subprocess.check_call(start_process)
            result = 0

    if result != 0:
        raise ValueError(
            f"Error when executing {action} in daemon {daemon}. Exit status: {result}")


def check_all_daemon_status():
    daemons_status = {}

    if sys.platform == WINDOWS:
        current_daemon = 'WAZUH_AGENT_WIN'
        daemons_status[current_daemon] = check_if_process_is_running(WAZUH_AGENT_WIN)
    else:
        control_status_output = subprocess.run([WAZUH_CONTROL_PATH, 'status'],
                                                stdout=subprocess.PIPE).stdout.decode()
        for lines in control_status_output.splitlines():
            daemon_status_tokens = lines.split()
            current_daemon = daemon_status_tokens[0]
            daemon_status = ' '.join(daemon_status_tokens[1:])
            is_running = daemon_status == 'is running...'
            daemons_status[current_daemon] = is_running
    return daemons_status


def wait_expected_daemon_status(target_daemon=None, running_condition=True, timeout=10, extra_sockets=[]):
    """Wait until Wazuh daemon's status matches the expected one. If timeout is reached and the status didn't match,
       it raises a TimeoutError.

    Args:
        target_daemon (str, optional):  Wazuh daemon to check. Default `None`. None means all.
        running_condition (bool, optional): True if the daemon is expected to be running False
            if it is expected to be stopped. Default `True`.
        timeout (int, optional): Timeout value for the check. Default `10` seconds.
        extra_sockets (list, optional): Additional sockets to check. They may not be present in default configuration.

    Raises:
        TimeoutError: If the daemon status is wrong after timeout seconds.
    """
    condition_met = False
    start_time = time.time()
    elapsed_time = 0

    while elapsed_time < timeout and not condition_met:
        if sys.platform == WINDOWS:
            # Query the Windows Service Control Manager instead of relying on
            # whether the process exists: a service in START_PENDING still has a
            # live process but is not yet operational, and tests that race on
            # "process exists" would proceed against a not-yet-ready service.
            # sc query is the authoritative source for service state on Windows.
            state, _ = _query_service_state()
            is_running = (state == 'RUNNING')
            condition_met = is_running == running_condition
        else:
            control_status_output = subprocess.run([WAZUH_CONTROL_PATH, 'status'],
                                                   stdout=subprocess.PIPE).stdout.decode()
            condition_met = True
            for lines in control_status_output.splitlines():
                daemon_status_tokens = lines.split()
                current_daemon = daemon_status_tokens[0]
                daemon_status = ' '.join(daemon_status_tokens[1:])
                daemon_running = daemon_status == 'is running...'
                if current_daemon == target_daemon or target_daemon is None:
                    if current_daemon in WAZUH_SOCKETS.keys():
                        socket_set = {path for path in WAZUH_SOCKETS[current_daemon]}
                    else:
                        socket_set = set()
                    # We remove optional sockets and add extra sockets to the set to check
                    socket_set.difference_update(WAZUH_OPTIONAL_SOCKETS)
                    socket_set.update(extra_sockets)
                    # Check specified socket/s status
                    for socket in socket_set:
                        if os.path.exists(socket) != running_condition:
                            condition_met = False
                    if daemon_running != running_condition:
                        condition_met = False
        if not condition_met:
            time.sleep(1)
        elapsed_time = time.time() - start_time

    if not condition_met:
        raise TimeoutError(f"{target_daemon} does not meet condition: running = {running_condition}")
    return condition_met


def check_if_process_is_running(process_name):
    """Check if process is running.

    Args:
        process_name (str): Name of process.

    Returns
        boolean: True if process is running, False otherwise.
    """
    is_running = False
    try:
        is_running = process_name in (p.name() for p in psutil.process_iter())
    except psutil.NoSuchProcess:
        pass

    return is_running


def search_process_by_command(search_cmd: str) -> Union[psutil.Process, None]:
    """Search a process by its command

    Args:
        search_cmd (str): Name of the command to be fetched.

    Returns:
        proc (psutil.Process | None): First occurrence of the process object matching the `search_cmd` or
            None if no process has been found.
    """
    if not isinstance(search_cmd, str):
        TypeError(f"`search_cmd` must be a str, but a {type(search_cmd)} was passed.")
    if search_cmd == '':
        TypeError('`search_cmd` must not be an empty string.')

    for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        command = next((command for command in process.cmdline() if search_cmd in command), None)
        if command:
            return process


def _query_service_state() -> Tuple[str, str]:
    """Query the current Wazuh service state from the platform authority.

    Windows: parses ``sc query WazuhSvc`` and returns the STATE token (e.g.
    RUNNING, START_PENDING, STOPPED). Non-Windows: parses ``wazuh-control
    status`` and returns the line for ``wazuh-modulesd`` (the daemon that
    hosts SCA) normalized to RUNNING/STOPPED.

    Returns:
        tuple[str, str]: (state, raw_output). ``state`` is one of RUNNING,
        START_PENDING, STOP_PENDING, STOPPED, UNKNOWN. ``raw_output`` is the
        full command output for diagnostic purposes.
    """
    if sys.platform == WINDOWS:
        proc = subprocess.run(["sc", "query", "WazuhSvc"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        raw = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
        match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", raw)
        state = match.group(1).upper() if match else 'UNKNOWN'
        return state, raw

    proc = subprocess.run([WAZUH_CONTROL_PATH, 'status'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    raw = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
    state = 'UNKNOWN'
    for line in raw.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != AGENT_MODULES_DAEMON:
            continue
        rest = ' '.join(tokens[1:])
        state = 'RUNNING' if rest == 'is running...' else 'STOPPED'
        break
    return state, raw


def collect_service_diagnostics(log_path: str = None, tail_lines: int = 80,
                                highlight_patterns: dict = None) -> dict:
    """Collect a snapshot of service/process/log state for failure diagnostics.

    Used when a fixture-level wait on a log pattern times out. The snapshot
    answers: "was the service actually RUNNING?", "are the expected processes
    alive?", and "what did the log last say?" — so CI failures point at a root
    cause instead of just a timeout.

    The ``highlight_patterns`` argument turns the log sweep into targeted
    evidence collection: given a mapping ``{label: regex}``, the diagnostics
    report, for each label, how many log lines matched and shows the first and
    last matching line. That pulls the needle out of a log dominated by noise
    (keep-alives, syslog reads) without any reviewer having to scroll.

    Args:
        log_path (str, optional): File whose tail should be included.
        tail_lines (int): Number of trailing lines to read from log_path.
        highlight_patterns (dict[str, str], optional): ``{label: regex}``. For
            each label, ``highlights[label]`` is a dict with ``count``,
            ``first`` and ``last`` (stripped matching lines, or None).

    Returns:
        dict with keys ``service_state``, ``service_raw``, ``processes`` and
        (if log_path provided) ``log_tail`` and ``highlights``.
    """
    state, raw = _query_service_state()
    processes = []
    wazuh_names = {'wazuh-agentd', 'wazuh-execd', 'wazuh-modulesd',
                   'wazuh-logcollector', 'wazuh-syscheckd',
                   'WazuhSvc.exe', 'wazuh-agent.exe'}
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        name = proc.info.get('name') or ''
        if any(w in name for w in wazuh_names):
            processes.append(f"{name}(pid={proc.info.get('pid')})")

    diag = {
        'service_state': state,
        'service_raw': raw,
        'processes': processes,
    }

    if log_path and os.path.isfile(log_path):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                lines = f.readlines()
            diag['log_tail'] = ''.join(lines[-tail_lines:])

            if highlight_patterns:
                compiled = {label: re.compile(pat) for label, pat in highlight_patterns.items()}
                highlights = {label: {'count': 0, 'first': None, 'last': None}
                              for label in highlight_patterns}
                for line in lines:
                    for label, pattern in compiled.items():
                        if pattern.search(line):
                            entry = highlights[label]
                            entry['count'] += 1
                            stripped = line.rstrip()
                            if entry['first'] is None:
                                entry['first'] = stripped
                            entry['last'] = stripped
                diag['highlights'] = highlights
        except OSError as exc:
            diag['log_tail'] = f"<could not read {log_path}: {exc}>"

    return diag
