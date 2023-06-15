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
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd import patterns
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils import callbacks


monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
monitor.start(callback=callbacks.generate_callback(patterns.SID_NOT_FOUND))

```
