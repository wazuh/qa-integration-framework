from queue import Queue
import ssl
from typing import List, Literal, Any

from wazuh_testing.constants.paths.configurations import BASE_CONF_PATH
from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils.certificate_controller import CertificateController

from .simulator_interface import SimulatorInterface


class AuthdSimulator(SimulatorInterface):
    """
    Simulates the behavior of an Authd server.

    Attributes:
        server_ip (str): The IP address of the Authd server. Defaults to '127.0.0.1'.
        port (int): The port number of the Authd server. Defaults to 1515.
        running (bool): The actual status of the simulator. Initial state False.
        secret (str): The secret key used by the Authd server. Defaults to 'SuperSecretKey'.
        mode (Literal['ACCEPT', 'REJECT']): The mode of operation for the simulator. Valid values are 'ACCEPT'
                                            and 'REJECT'. Defaults to 'ACCEPT'.
        key_path (str): The file path for the SSL key used by the server. Defaults to 'BASE_CONF_PATH/manager.key'.
        cert_path (str): The file path for the SSL certificate used by the server. Defaults to 'BASE_CONF_PATH/manager.cert'.
        queue (Queue): The MitM Queue object used for storing received messages.

    Note:
        The `key_path` and `cert_path` parameters should be set to appropriate file paths prior to initializing the simulator.
    """
    MODES = ['ACCEPT', 'REJECT']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1515,
                 secret: str = 'SuperSecretKey',
                 mode: Literal['ACCEPT', 'REJECT'] = 'ACCEPT',
                 key_path: str = f'{BASE_CONF_PATH}/manager.key',
                 cert_path: str = f'{BASE_CONF_PATH}/manager.cert') -> None:
        """
        Initializes the Authd simulator with the specified configuration parameters.

        Args:
            server_ip (str): The IP address of the Authd server.
            port (int): The port number of the Authd server
            secret (str): The secret key used by the Authd server.
            mode (Literal['ACCEPT', 'REJECT']): The mode of operation for the simulator.
            key_path (str): The file path for the SSL key used by the server.
            cert_path (str): The file path for the SSL certificate used by the server.
        """
        super().__init__(server_ip=server_ip, port=port, running=False)

        self.secret = secret
        self.mode = mode
        self.key_path = key_path
        self.cert_path = cert_path

        self.agent_id = 0
        self.cert_controller = CertificateController()

        self.__mitm = ManInTheMiddle(address=(self.server_ip, self.port),
                                     family='AF_INET', connection_protocol='SSL',
                                     func=self.__authd_response_simulation)

    # Properties

    @property
    def mode(self) -> Literal['ACCEPT', 'REJECT']:
        """
        Get the mode of operation for the simulator.

        Returns:
            Literal['ACCEPT', 'REJECT']: The current mode of operation.
        """
        return self.__mode

    @mode.setter
    def mode(self, mode: Literal['ACCEPT', 'REJECT']) -> None:
        """
        Set the mode of operation for the simulator.

        Args:
            mode (Literal['ACCEPT', 'REJECT']): The mode of operation to set.

        Raises:
            ValueError: If the specified mode is not 'ACCEPT' or 'REJECT'.
        """
        if mode.upper() not in self.MODES:
            raise ValueError('Invalid mode.')

        self.__mode = mode.upper()

    @property
    def queue(self) -> Queue:
        """
        Get the queue used for storing received messages.

        Returns:
            Queue: MitM queue object that stores received messages.
        """
        return self.__mitm.queue

    # Methods

    def start(self) -> None:
        """
        Generates a certificate for the SSL server and starts MitM connection.

        It prepares the SSL configuration for the MitM listener by specifying
        he connection protocol as 'ssl.PROTOCOL_TLS_CLIENT' and providing the
        generated certificate and keyfile paths.
        """
        if self.running:
            return
        self.__generate_certificates()
        self.__mitm.start()
        self.__mitm.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLS_SERVER,
                                                   certificate=self.cert_path, keyfile=self.key_path)
        self.running = True

    def shutdown(self) -> None:
        """
        Shutdown Man in the middle connection.
        """
        if not self.running:
            return
        self.__mitm.shutdown()
        self.running = False

    def clear(self) -> None:
        """
        Clear sockets after each response.

        By default, the sockets stop handling connections after one successful
        connection, and they need to be cleared to be ready for the next connection.
        """
        while not self.__mitm.queue.empty():
            self.__mitm.queue.get_nowait()
        self.__mitm.event.clear()

    # Internal methods.

    def __authd_response_simulation(self, received: Any) -> None:
        """Simulates a Authd response for an agent request.

        Args:
            received (Any): The received message to process.

        Raises:
            ValueError: If the received message is empty.
        """
        if not received:
            raise ValueError('Received message is empty.')

        if self.mode == 'REJECT':
            # Simulate a reject from authd.
            self.__mitm.event.set()
            return b'ERROR'

        self.agent_id += 1

        # Parse the received message and create the simulated response.
        msg_sections = received.decode().split(' ')
        agent_info = self.__set_agent_info(msg_sections)
        response = f"OSSEC K:'{self.agent_id:03d} {agent_info['name']} {agent_info['ip']} {self.secret}'\n"

        # Notify the MitM event.
        self.__mitm.event.set()

        return response.encode()

    def __set_agent_info(self, msg_sections: List[str]) -> dict:
        """Extracts agent information from the message sections.

        Args:
            msg_sections (List[str]): The list of message sections to process.

        Returns:
            dict: A dictionary containing the agent information with the following keys:
                - 'id': The agent ID (same as self.agent_id).
                - 'name': The agent name extracted from the message sections.
                - 'ip': The agent IP address extracted from the message sections.
        """
        agent_info = {'id': self.agent_id, 'name': None, 'ip': None}

        for section in msg_sections:
            # Extract the name and ip from the message sections.
            if section.startswith('A:'):
                agent_info['name'] = section.split("'")[1]
            elif section.startswith('IP:'):
                agent_info['ip'] = section.split("'")[1]

        # If the IP has no value set it as any.
        agent_info['ip'] = agent_info.get('ip') or 'any'
        if agent_info['ip'] == 'src':
            # The IP is src so set the actual agent IP.
            agent_info['ip'] = self.__mitm.listener.last_address[0]

        return agent_info

    def __generate_certificates(self):
        """Generates and stores certificates for the root CA.

        It signs the root CA certificate with the root CA private key using 
        the specified digest algorithm.
        The generated root CA certificate and private key are then stored 
        at the provided paths.
        """
        self.cert_controller.root_ca_cert.sign(
            self.cert_controller.root_ca_key, self.cert_controller.digest)
        self.cert_controller.store_private_key(
            self.cert_controller.root_ca_key, self.key_path)
        self.cert_controller.store_ca_certificate(
            self.cert_controller.root_ca_cert, self.cert_path)
