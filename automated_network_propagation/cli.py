from option_parser import OptionParser


class AutomatedNetworkPropagationOptionParser(OptionParser):
    class Namespace:
        host: str
        port: int
        log_path: str

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(
                    description='Run a HTTP server with SSE capabilities that propagates network information.'
                ) | kwargs
            )
        )

        self.add_argument(
            '--host',
            default='127.0.0.1',
            help='The address on which to listen.'
        )

        self.add_argument(
            '--port',
            type=int,
            default=80,
            help='The path of a directory from which to read transcripts.'
        )

        self.add_argument(
            '--log-path',
            default='automated_network_propagation_server.log',
            help='The path where to store logs.'
        )
