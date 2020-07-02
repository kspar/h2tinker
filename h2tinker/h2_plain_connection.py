import socket

from h2tinker import log
from h2tinker.h2_connection import H2Connection


class H2PlainConnection(H2Connection):
    """
    Plain non-TLS HTTP/2 connection (h2c).
    """

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def setup(self, host: str, port: int = 80):
        """
        Set the connection up by creating the TCP connection and then performing the HTTP/2 handshake.
        :param host: host where to connect, e.g. example.com or 127.0.0.1
        :param port: TCP port where to connect
        """
        super().setup(host, port)
        self.host = host
        self.port = port
        self.sock.connect((host, port))
        log.debug('Socket connected')
        self._send_preface()
        self._send_initial_settings()
        self._setup_wait_loop()
        self.is_setup_completed = True
        log.info("Completed HTTP/2 connection setup")


