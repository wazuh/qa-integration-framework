from abc import ABC, abstractmethod


class SimulatorInterface(ABC):
    def __init__(self, server_ip: str, port: int) -> None:
        self.server_ip = server_ip
        self.port = port

    @abstractmethod
    def start():
        pass

    @abstractmethod
    def shutdown():
        pass
