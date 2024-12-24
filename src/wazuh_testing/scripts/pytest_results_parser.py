import argparse
import glob
import re
from collections import defaultdict
from copy import copy
from os.path import exists, isfile, sep, extsep

STATUS_DICT = {'passed': 0, 'xpassed': 0, 'skipped': 0, 'xfailed': 0, 'failed': 0}

STATUS_COMPATIBILITY = {
    'passed': 'passed',
    'error': 'failed',
    'failed': 'failed',
    'xfail': 'xfailed',
    'xpass': 'xpassed',
    'skipped': 'skipped',
}

OUTPUT = """
## Test report
Add zip here

## Test results

---
| **Test name** | **Pass** | **XPass** | **Skip** | **XFail** | **Fail** | **Issues Ref.** | **Status** |
|--|--|--|--|--|--|--|--|
"""


def parse_test_content(path):
    with open(path, 'r') as f:
        file = f.read()
    try:
        result_dict = defaultdict(lambda: copy(STATUS_DICT))
        for match in re.findall(
            r'([\w_./]+)::.+(PASSED|ERROR|FAILED|XFAIL|XPASS|SKIPPED)',
            file,
            re.MULTILINE,
        ):
            test_name = match[0]
            status = match[1].lower()

            result_dict[test_name][STATUS_COMPATIBILITY[status]] += 1

        return result_dict

    except AttributeError:
        print(f'Could not retrieve results from this test: {path}')
        exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Pytest Result Parser (Wazuh)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-f',
        '--file',
        dest='file_path',
        action='store',
        help='Path to the test result file.',
    )
    group.add_argument(
        '-p',
        '--path',
        dest='tests_dir',
        action='store',
        help='Path to the test result files. All files within will be read (not recursive)',
    )

    return parser.parse_args()


def update_output(results):
    global OUTPUT

    for test_name, statuses in results.items():
        if statuses['failed'] > 0:
            check = ':red_circle:'
        elif (
            statuses['skipped'] > 0
            or statuses['xfailed'] > 0
            or statuses['xpassed'] > 0
        ):
            check = ':yellow_circle:'
        elif statuses['passed'] == 0:
            check = ':red_circle:'
        else:
            check = ':green_circle:'

        new_line = (
            f"| {test_name} | {statuses['passed']} | {statuses['xpassed']} | {statuses['skipped']} | "
            f"{statuses['xfailed']} | {statuses['failed']} | "
            f"{'insert issue link' if check != ':green_circle:' else ''} | {check} |"
        )

        OUTPUT = f'{OUTPUT}{new_line}\n'


def main():
    arguments = parse_arguments()
    file_path = arguments.file_path
    tests_dir = arguments.tests_dir

    if file_path:
        if not exists(file_path):
            print(f'Path is not valid: {file_path}')
            exit(1)

        update_output(parse_test_content(file_path))

    else:
        if not exists(tests_dir):
            print(f'Path is not valid: {tests_dir}')
            exit(1)

        for test_path in [
            t for t in sorted(glob.glob(f'{tests_dir}{sep}*{extsep}txt')) if isfile(t)
        ]:
            update_output(parse_test_content(test_path))

    print(OUTPUT)


if __name__ == '__main__':
    main()
