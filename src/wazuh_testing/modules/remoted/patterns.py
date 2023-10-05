from . import PREFIX

INVALID_VALUE_FOR_ELEMENT = fr"{PREFIX}.*Invalid value for element.*"
CONFIGURATION_ERROR = r".*{severity}:.*Configuration error at '{path}'.*"

INVALID_VALUE_FOR_PORT_NUMBER = fr"{PREFIX}.*Invalid port number.*"
CONFIGURATION_ERROR_PORT = r".*{severity}: \\(\\d+\\): Invalid port number: '{port}'.*"
