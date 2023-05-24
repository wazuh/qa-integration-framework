# qa-integration-framework
Wazuh QA framework for integration tests

## Installation 

1. Clone the framework's repo: `git clone https://github.com/wazuh/qa-integration-framework.git`
2. Install python deps: `apt-get install python3 python3-dev python3-pip -y`
3. Install the framework: `pip install qa-integration-framework/`
    > It will also install all the dependencies from the requirements.txt automatically.

## Usage

You can just import it from the test suite as any other python library
```python
from wazuh_testing.constants.paths.logs import OSSEC_LOG_PATH
from wazuh_testing.modules.analysisd.testrule import patterns
from wazuh_testing.tools.file_monitor import FileMonitor, generate_callback


FileMonitor(OSSEC_LOG_PATH, generate_callback(patterns.SID_NOT_FOUND))

```
