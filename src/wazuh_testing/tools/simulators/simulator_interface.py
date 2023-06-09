from abc import ABC, abstractmethod


class SimulatorInterface(ABC):
    
    server_ip: str
    port: int

    @abstractmethod
    def start():
        pass

    @abstractmethod
    def shutdown():
        pass
