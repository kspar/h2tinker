# H2Tinker

H2Tinker is a minimalistic low-level HTTP/2 client implementation in Python.

It is based on [scapy](https://github.com/secdev/scapy) and also enables directly sending scapy-crafted frames. On top of scapy, h2tinker provides
* HTTP/2 connection setup and management,
* TCP and TLS connection setup and management,
* a user-friendly documented and typed API for creating different frames and requests,
* documentation and examples on how different attacks can be implemented.

## Quickstart

See [Examples](https://github.com/kspar/h2tinker/wiki/Examples) to get started.

## Installation

h2tinker is available in the [Python Package Index](https://pypi.org/project/h2tinker) and can be installed with pip:
```
pip3 install h2tinker
```

