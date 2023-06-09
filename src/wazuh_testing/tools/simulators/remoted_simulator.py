from .simulator_interface import SimulatorInterface


class RemotedSimulator(SimulatorInterface):
    def __init__(self, server_ip: str = '', port: int = 1) -> None:
        super().__init__(server_ip, port)

    def start():
        pass

    def shutdown():
        pass
