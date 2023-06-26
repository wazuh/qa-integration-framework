import os
from wazuh_testing.constants.paths import WAZUH_PATH


ACTIVE_RESPONSE_BINARIES = os.path.join(WAZUH_PATH, 'active-response', 'bin')
FIREWALL_DROP_BIN = os.path.join(ACTIVE_RESPONSE_BINARIES, 'firewall-drop')
