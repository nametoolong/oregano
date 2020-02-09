# Oregano

MITM proxy for Tor, with GnuTLS's length hiding capability.

## Capabilities

Designed as a research software, Oregano has more uses than research:

* Make your Tor research pleasant

  Inject, drop or tamper with any cells between a client and its guard. Currently this is poorly documented, but it is always easier to hack 2000 lines of Python code than the whole Tor daemon.

* Turn anything with an open ORPort into a bridge

  Whether it is a relay, a bridge or another MITM box, use Oregano to proxy its ORPort and use it as a bridge.

* Tease the vanilla Tor daemon

  Combining the two points above, Oregano can create impossible conditions. Make malformed cells and try to find bugs in the original Tor software. Or wrap the only middle node in a chutney network as a bridge and watch Tor's path selection code go crazy.

* Fight against flow analysis

  With GnuTLS's length hiding APIs, you can hide your flow characteristics in extra padding.

* Go through your corporate firewall, or even GFW

  Even if your working place has a sophisticated Israeli firewall specially tuned for detecting Tor traffic, GnuTLS's length hiding capability and Oregano's ability to inject anything into a link help you sneak through it. See [PIPIResistanceHandler](https://github.com/nametoolong/oregano/blob/master/oregano/configuration.py#L64) for an example.

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
* [python-gnutls](https://github.com/AGProjects/python-gnutls)
* [cryptography](https://cryptography.io/)
* [PySocks](https://github.com/Anorov/PySocks) (only needed when proxy is set)

## Security

This normally compromises anonymity by creating a bunch of side channels. However, given its TLS link manipulation nature, sometimes this might also help you.
