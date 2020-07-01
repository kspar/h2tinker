import socket
import ssl

import scapy.contrib.http2 as h2
import scapy.supersocket as supersocket

from h2tinker import log
from h2tinker.h2_connection import H2Connection
from h2tinker.assrt import assert_error


class H2TLSConnection(H2Connection):

    def __init__(self):
        super().__init__()
        assert_error(bool(ssl.HAS_ALPN), 'TLS ALPN extension not available but it is required for HTTP/2 over TLS')

    def setup(self, host: str, port: int = 443):
        super().setup(host, port)
        self.host = host
        self.port = port

        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        assert_error(len(addrinfos) > 0, 'No TCP socket info available for host {} and port {}', host, port)
        addrinfo = addrinfos[0]
        log.debug('Endpoint addrinfo: {}'.format(addrinfo))

        raw_sock = socket.socket(addrinfo[0], addrinfo[1], addrinfo[2])
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.set_alpn_protocols(['h2'])
        ssl_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=host)
        ssl_sock.connect(addrinfo[4])

        assert_error('h2' == ssl_sock.selected_alpn_protocol(), 'Server did not agree to use HTTP/2 in ALPN')

        self.sock = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
        log.debug("Socket connected")

        self._send_preface()
        self._send_initial_settings()
        self._setup_wait_loop()
        self.is_setup_completed = True
        log.info("Completed HTTP/2 connection setup")
