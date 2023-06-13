import pytest

# Marks Execution

TIER0 = pytest.mark.tier(level=0)
TIER1 = pytest.mark.tier(level=1)
TIER2 = pytest.mark.tier(level=2)

WINDOWS = pytest.mark.win32
LINUX = pytest.mark.linux
MACOS = pytest.mark.darwin
SOLARIS = pytest.mark.sunos5

AGENT = pytest.mark.agent
SERVER = pytest.mark.server

# Local internal options
WINDOWS_DEBUG = 'windows.debug'
SYSCHECK_DEBUG = 'syscheck.debug'
VERBOSE_DEBUG_OUTPUT = 2
