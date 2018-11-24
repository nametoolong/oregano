# Oregano

MITM proxy for Tor, with GnuTLS's length hiding capability to evade some kinds of fingerprinting against Tor protocol.

## Installation

Make sure Python 2.7 is installed. Download a Windows release or manually install dependencies. That's all.

## Usage

Edit `configuration.py` under directory `oregano` for configuration and run module `oregano.proxy`.
```
python -m oregano.proxy
```

Then set `UseBridges` or use a Tor controller to instruct a Tor client to connect to the listening interface. Or play around with ARP spoofing and redirect someone's bridge connection. Or whatever.
```
UseBridges 1
Bridge 127.0.0.1:40056
```

## Dependencies

* Python 2.7
* [GnuTLS](https://gnutls.org/)
* [python-gnutls](https://github.com/nametoolong/python-gnutls)
* [PyCryptodome](https://www.pycryptodome.org/)
* [eccsnacks](https://github.com/nnathan/eccsnacks)
* [PySocks](https://github.com/Anorov/PySocks) (only needed when proxy is set)

## Security

This compromises anonymity.
