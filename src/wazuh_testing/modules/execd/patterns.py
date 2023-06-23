from . import PREFIX


# Callback patterns to find events in log file.
EXECD_STARTED = fr"{PREFIX}Input message handler thread started."
EXECD_THREAD_READY = r'DEBUG: Received message: '
