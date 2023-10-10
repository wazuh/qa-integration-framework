from . import PREFIX

INVALID_VALUE_FOR_ELEMENT = fr"{PREFIX}.*Invalid value for element.*"
CONFIGURATION_ERROR = r".*{severity}:.*Configuration error at '{path}'.*"

INVALID_VALUE_FOR_PORT_NUMBER = fr"{PREFIX}.*Invalid port number.*"
CONFIGURATION_ERROR_PORT = r".*{severity}: \\(\\d+\\): Invalid port number: '{port}'.*"

IGNORED_INVALID_PROTOCOL = r".*WARNING:.* Ignored invalid value '{protocol}' for 'protocol'.*"
ERROR_GETTING_PROTOCOL = fr"{PREFIX}.* Error getting protocol. Default value \(TCP\) will be used.*"
DETECT_REMOTED_STARTED = r".*Started.*Listening on port {port}\/{protocol_valid_upper} \({connection}\).*"
