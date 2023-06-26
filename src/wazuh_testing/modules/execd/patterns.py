from . import PREFIX


# Callback patterns to find events in log file.
EXECD_THREAD_STARTED = fr"{PREFIX}Input message handler thread started."
EXECD_RECEIVED_MESSAGE = r'.*DEBUG: Received message.*'
EXECD_EXECUTING_COMMAND = r'.*DEBUG: Executing command.*'
