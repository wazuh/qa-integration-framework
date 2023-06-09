from abc import ABC, abstractmethod


class SimulatorInterface(ABC):

    @property
    @abstractmethod
    def server_ip(self):
        pass

    @property
    @abstractmethod
    def port(self):
        pass

    @abstractmethod
    def start():
        pass

    @abstractmethod
    def shutdown():
        pass
