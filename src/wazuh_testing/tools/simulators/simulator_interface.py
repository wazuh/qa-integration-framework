from abc import ABC, abstractmethod


class SimulatorInterface(ABC):
    def __init__(self, server_ip: str, port: int, running: bool) -> None:
        self.server_ip = server_ip
        self.port = port
        self.running = running

    @abstractmethod
    def start():
        pass

    @abstractmethod
    def shutdown():
        pass
