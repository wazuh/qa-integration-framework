from ast import List
import ssl
import time
from typing import Literal, Any

from wazuh_testing.tools.mitm import ManInTheMiddle
from wazuh_testing.utils.certificate_controller import CertificateController


class AuthdSimulator:
    def __init__(self,
                 ip_address: str = '127.0.0.1',
                 port: int = 1515,
                 secret: str = 'SuperSecretKey',
                 mode: Literal['ACCEPT', 'REJECT'] = 'ACCEPT',
                 key_path: str = '/etc/manager.key',
                 cert_path: str = '/etc/manager.cert') -> None:

        self.cert_controller = CertificateController()
        self.key_path = key_path
        self.cert_path = cert_path
        self.mode = mode
        self.secret = secret
        self.agent_id = 0
        self.enrollment = ManInTheMiddle(address=(ip_address, port),
                                         family='AF_INET',
                                         connection_protocol='SSL',
                                         func=self.__authd_response_simulation)

    # Properties

    @property
    def mode(self) -> Literal['ACCEPT', 'REJECT']:
        return self.__mode

    @mode.setter
    def mode(self, mode: Literal['ACCEPT', 'REJECT']) -> None:
        if mode.upper() not in ['ACCEPT', 'REJECT']:
            raise ValueError('Invalid mode.')

        self.__mode = mode.upper()

    @property
    def queue(self):
        return self.enrollment.queue

    # Functions

    def start(self):
        """
        Generates certificate for the SSL server and starts server sockets
        """
        self.__generate_certificates()
        self.enrollment.start()
        self.enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLS_CLIENT,
                                                       certificate=self.cert_path, keyfile=self.key_path)

    def shutdown(self):
        """
        Shutdown sockets
        """
        self.enrollment.shutdown()

    def clear(self):
        """
        Clear sockets after each response. By default, they stop handling connections
        after one successful connection, and they need to be cleared afterwards
        """
        while not self.enrollment.queue.empty():
            self.enrollment.queue.get_nowait()
        self.enrollment.event.clear()

    # Internal functions

    def __authd_response_simulation(self, received: Any) -> None:
        if received is None:
            raise ValueError('"None" is not a valid message.')

        if self.mode == 'REJECT':
            self.enrollment.event.set()
            return b'ERROR'

        self.agent_id += 1

        msg_sections = received.decode().split(' ')
        agent_info = self.__set_agent_info(msg_sections)
        response = f"OSSEC K:'{self.agent_id:03d} {agent_info['name']} {agent_info['ip']} {self.secret}'\n"

        self.enrollment.event.set()
        return response.encode()

    def __set_agent_info(self, msg_sections: List[str]) -> dict:
        agent_info = {'id': self.agent_id, 'name': None, 'ip': None}

        for section in msg_sections:
            if section.startswith('A:'):
                agent_info['name'] = section.split("'")[1]
            elif section.startswith('IP:'):
                agent_info['ip'] = section.split("'")[1]

        agent_info['ip'] = agent_info.get('ip', 'any') or 'any'
        if agent_info['ip'] == 'src':
            agent_info['ip'] = self.enrollment.listener.last_address[0]

        return agent_info

    def __generate_certificates(self):
        self.cert_controller.root_ca_cert.sign(
            self.cert_controller.root_ca_key, self.cert_controller.digest)
        self.cert_controller.store_private_key(
            self.cert_controller.root_ca_key, self.key_path)
        self.cert_controller.store_ca_certificate(
            self.cert_controller.root_ca_cert, self.cert_path)
