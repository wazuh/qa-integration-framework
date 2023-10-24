from . import PREFIX

INVALID_VALUE_FOR_ELEMENT = fr"{PREFIX}.*Invalid value for element.*"
CONFIGURATION_ERROR = r".*{severity}:.*Configuration error at '{path}'.*"

INVALID_VALUE_FOR_PORT_NUMBER = fr"{PREFIX}.*Invalid port number.*"
CONFIGURATION_ERROR_PORT = r".*{severity}: \\(\\d+\\): Invalid port number: '{port}'.*"

IGNORED_INVALID_PROTOCOL = r".*WARNING:.* Ignored invalid value '{protocol}' for 'protocol'.*"
ERROR_GETTING_PROTOCOL = fr"{PREFIX}.* Error getting protocol. Default value \(TCP\) will be used.*"
DETECT_REMOTED_STARTED = r".*Started.*Listening on port {port}\/{protocol_valid_upper} \({connection}\).*"

WARNING_SYSLOG_TCP_UDP = r".*WARNING:.*Only secure connection supports TCP and UDP at the same time. " \
                         r"Default value \(TCP\) will be used.*"

ERROR_BIND_PORT = r".*CRITICAL: \(\d+\): Unable to Bind port '1514' due to \[\(\d+\)\-\(Cannot assign requested address\)\]"

ERROR_QUEUE_SIZE_SYSLOG = r".*ERROR: Invalid option \<queue_size\> for Syslog remote connection."

WARNING_QUEUE_SIZE_TOO_BIG = r".*WARNING: Queue size is very high. The application may run out of memory."

WARNING_INVALID_VALUE_FOR = r".*WARNING: \(\d+\): Invalid value '.*' in '{option}' option. Default value will be used.*"

DETECT_SYSLOG_ALLOWED_IPS = r".*Remote syslog allowed from: \'{syslog_ips}\'.*"

ERROR_INVALID_IP = r".*ERROR: \(\d+\): Invalid ip address: '{ip}'.*"

ERROR_IN_CONFIGURATION = r".*{severity}:.*Configuration error at '{conf_path}'.*"
