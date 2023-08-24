import subprocess


def run_with_output(commands: list) -> bytes:
    return subprocess.check_output(commands)


def run(commands: list) -> int:
    return subprocess.call(commands)


def get_rules_path():
    return str(run_with_output(['auditctl', '-l']))
