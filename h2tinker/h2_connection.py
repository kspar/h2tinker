import time
import typing as T
from abc import ABC

import scapy.contrib.http2 as h2
from scapy.compat import hex_bytes
from scapy.data import MTU

from h2tinker import log
from h2tinker.assrt import assert_error
from h2tinker.frames import is_frame_type, has_ack_set, create_settings_frame


class H2Connection(ABC):
    PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')

    def __init__(self, ):
        self.host = None
        self.port = None
        self.sock = None
        self.is_setup_completed = False

    def _check_setup_completed(self):
        assert_error(self.is_setup_completed, 'Connection setup has not been completed, call setup(...) '
                                              'before operating with the connection')

    def setup(self, host: str, port: int):
        assert_error(not self.is_setup_completed, 'Connection setup has already been completed with '
                                                  '{}:{}', self.host, self.port)

    def create_request_frames(self, method: str, path: str, stream_id: int,
                              headers: T.Dict[str, str] = None,
                              body: T.Optional[str] = None) -> h2.H2Seq:

        header_table = h2.HPackHdrTable()
        req_str = (':method {}\n'
                   ':path {}\n'
                   ':scheme http\n'
                   ':authority {}:{}\n').format(method, path, self.host, self.port)

        if headers is not None:
            req_str += '\n'.join(map(lambda e: '{}: {}'.format(e[0], e[1]), headers.items()))

        # noinspection PyTypeChecker
        return header_table.parse_txt_hdrs(
            bytes(req_str.strip(), 'UTF-8'),
            stream_id=stream_id,
            body=body
        )

    def create_dependant_request_frames(self, method: str, path: str, stream_id: int,
                                        dependency_stream_id: int = 0,
                                        dependency_weight: int = 0,
                                        dependency_is_exclusive: bool = False,
                                        headers: T.Dict[str, str] = None,
                                        body: T.Optional[str] = None) -> h2.H2Seq:

        req_frameseq = self.create_request_frames(method, path, stream_id, headers, body)
        dep_req_frames = []
        for f in req_frameseq.frames:
            if is_frame_type(f, h2.H2HeadersFrame):
                pri_hdr_frame = h2.H2PriorityHeadersFrame()
                pri_hdr_frame.stream_dependency = dependency_stream_id
                pri_hdr_frame.weight = dependency_weight
                pri_hdr_frame.exclusive = 1 if dependency_is_exclusive else 0
                pri_hdr_frame.hdrs = f.hdrs
                dep_req_frames.append(
                    h2.H2Frame(stream_id=f.stream_id, flags=f.flags | {'+'}) / pri_hdr_frame
                )
            else:
                dep_req_frames.append(f)

        req_frameseq.frames = dep_req_frames
        return req_frameseq

    def infinite_read_loop(self):
        self._check_setup_completed()
        log.info("Infinite read loop starting...")
        while True:
            frames = self._recv_frames()
            for f in frames:
                log.info("Read frame:")
                # TODO: respect log level
                f.show()

    def send_frames(self, *frames: h2.H2Frame):
        self._check_setup_completed()
        self._send_frames(*frames)

    def recv_frames(self) -> T.List[h2.H2Frame]:
        self._check_setup_completed()
        return self._recv_frames()

    def _setup_wait_loop(self):
        server_has_acked_settings = False
        we_have_acked_settings = False
        while not server_has_acked_settings or not we_have_acked_settings:
            frames = self._recv_frames()
            for f in frames:
                if is_frame_type(f, h2.H2SettingsFrame):
                    if has_ack_set(f):
                        log.info("Server acked our settings")
                        server_has_acked_settings = True
                    else:
                        log.info("Got server settings, acking")
                        self._ack_settings()
                        we_have_acked_settings = True

    def _ack_settings(self):
        self._send_frames(create_settings_frame(is_ack=True))
        log.info("Acked server settings")

    def _send_initial_settings(self):
        settings = [
            h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
            h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=2_147_483_647),
            h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_CONCURRENT_STREAMS, value=1000)
        ]
        self._send_frames(create_settings_frame(settings))
        log.info("Sent settings")

    def _send_frames(self, *frames: h2.H2Frame):
        b = bytes()
        for f in frames:
            b += bytes(f)
        self._send(b)

    def _send_preface(self):
        self._send(self.PREFACE)

    def _send(self, bytez):
        self.sock.send(bytez)

    def _recv_frames(self) -> T.List[h2.H2Frame]:
        chunk = self._recv()
        return h2.H2Seq(chunk).frames

    def _recv(self):
        while True:
            try:
                return self.sock.recv(MTU)
            except AssertionError:
                # Frame parsing failed on current data, try again in 100 ms
                time.sleep(0.1)
