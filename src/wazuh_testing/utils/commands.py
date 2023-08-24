# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import subprocess
import sys

from wazuh_testing.constants.platforms import WINDOWS


def run_local_command_returning_output(command):
    """Run local commands catching and returning the stdout in a variable. Nothing is displayed on the stdout.

    Args:
        command (string): Command to run.

    Returns:
        str: Command output.
    """
    if sys.platform == WINDOWS:
        run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    else:
        run = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE)

    return run.stdout.read().decode()


def run_with_output(commands: list) -> bytes:
    return subprocess.check_output(commands)


def run(commands: list) -> int:
    return subprocess.call(commands)


def get_rules_path():
    return str(run_with_output(['auditctl', '-l']))
