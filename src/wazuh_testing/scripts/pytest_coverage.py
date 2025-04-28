import argparse
import re
import subprocess
from os import chdir, remove
from os.path import basename, exists, join, dirname

PYTHON_MODULES = (
    'framework',  # Framework
    'apis/server_management',  # Management API
    'apis/communications',  # Communications API
)

COVERAGE_FILE = '.coverage'
COVERAGE_REPORT = ''
COVERAGE_REGEX = r'^([\w\/._-]+) +(\d+) +(\d+) +(\d+)\%$'
GLOBAL_STMTS = 0
GLOBAL_MISS = 0
TABLE_HEADER = """| | | | | |
|--|--|--|--|--|
| **Name** | **Stmts** | **Miss** | **Cover** | **Status** |
"""


def obtain_coverage(module):
    chdir(dirname(module))
    module_basename = basename(module)

    module_report = f'### {module_basename.upper()}\n\n{TABLE_HEADER}'
    subprocess.run(['coverage', 'run', '--omit=*test*', '--source', module_basename,
                    '-m', 'pytest', module_basename],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    coverage_result = subprocess.check_output(['coverage', 'report']).decode().strip()
    test_coverage_results = re.findall(COVERAGE_REGEX, coverage_result, re.MULTILINE)
    for test in test_coverage_results:
        # test_name stmts miss cover
        coverage = int(test[3])
        if coverage >= 75:
            check = ':green_square:'
        elif coverage >= 50:
            check = ':yellow_square:'
        elif coverage >= 25:
            check = ':orange_square:'
        else:
            check = ':red_square:'

        module_report = f'{module_report}| {test[0]} | {test[1]} | {test[2]} | {coverage}% | {check} |\n'

    global COVERAGE_REPORT
    COVERAGE_REPORT = f'{COVERAGE_REPORT}{module_report}\n'

    global GLOBAL_STMTS, GLOBAL_MISS
    GLOBAL_STMTS += int(test_coverage_results[-1][1])
    GLOBAL_MISS += int(test_coverage_results[-1][2])

    # Remove .coverage file
    exists(COVERAGE_FILE) and remove(COVERAGE_FILE)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Pytest Coverage (Wazuh)')
    parser.add_argument('-p', '--path', dest='wazuh_path', action='store', required=True,
                        help='Path to the Wazuh repository.')

    return parser.parse_args()


def main():
    arguments = parse_arguments()
    wazuh_path = arguments.wazuh_path

    if not exists(wazuh_path):
        print(f'Base Wazuh path is not valid: {wazuh_path}')
        exit(1)

    for module in PYTHON_MODULES:
        current_module_path = join(wazuh_path, module)

        if not exists(current_module_path):
            print(f'Wazuh module path is not valid: {current_module_path}')
            exit(1)

        obtain_coverage(current_module_path)

    print(COVERAGE_REPORT)
    print(f'\nOVERALL COVERAGE PERCENTAGE: {100 - int(GLOBAL_MISS * 100 / GLOBAL_STMTS)}%')


if __name__ == '__main__':
    main()
