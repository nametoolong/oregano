import collections
import logging
import signal
import socket
import SocketServer
import sys
import threading
import time
import traceback

from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.connection import TLSContext, X509Credentials
from gnutls.constants import X509_FMT_DER
from gnutls.errors import GNUTLSError

from Crypto.Hash import SHA1
from Crypto.IO import PEM
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence

from mesona.proxy import MITMServer, MITMHandler, MITMSettings, send_range_safe, is_ipv6_address

import oregano
from oregano.crypto import LowLevelSignature, NTorKey
from oregano.onion import *

HASH_LEN = 20
CURVE25519_KEY_LEN = 32

PLATFORM = "Oregano {version}".format(version=oregano.__version__)
DESCRIPTOR_TEMPLATE = '''
router {nickname} {address} {port} 0 0
platform {platform}
proto Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=3-4 LinkAuth=1 Microdesc=1-2 Relay=1-2
published {published}
fingerprint {fingerprint}
bandwidth {bandwidth}
onion-key
{onion_key}
signing-key
{signing_key}
ntor-onion-key {ntor_onion_key}
bridge-distribution-request none
reject *:*
tunnelled-dir-server
router-signature
'''.lstrip()
DIR_IDENTITY_RESPONSE_TEMPLATE = '''
HTTP/1.0 200 OK

Content-Type: application/octet-stream
Content-Encoding: identity

'''.lstrip().replace("\n", "\r\n")

NTorOnionKey = collections.namedtuple('NTorOnionKey', ("secret", "public"))

class ORError(Exception):
    pass

def encodePEMRawRSAPubKey(key):
    return PEM.encode(DerSequence([key.n, key.e]).encode(), "RSA PUBLIC KEY")

class ORMITMServer(MITMServer):
    def __init__(self, config, bind_and_activate=True):
        self.config = config

        if is_ipv6_address(self.config.listen_address):
            self.address_family = socket.AF_INET6

        with open(self.config.cert, 'rb') as f:
            self.encoded_cert = f.read()

        with open(self.config.key, 'r') as f:
            self.key = f.read()

        with open(self.config.onion_secret_key, 'r') as f:
            self.onion_secret_key = f.read()

        self.set_handler()

        self.server_context = TLSContext(X509Credentials(
            X509Certificate(self.encoded_cert, format=X509_FMT_DER),
            X509PrivateKey(self.key)), config.priority_string_as_server)
        self.client_context = TLSContext(X509Credentials(), config.priority_string_as_client)

        self.identity_pubkey = RSA.import_key(self.encoded_cert)
        self.identity_privkey = RSA.import_key(self.key)

        self.onion_privkey = RSA.import_key(self.onion_secret_key)

        ntor_onion_secret_key = self.config.ntor_onion_secret_key.decode("base64").strip()
        self.ntor_onion_key = NTorOnionKey(ntor_onion_secret_key, NTorKey(ntor_onion_secret_key).get_public())

        self.fingerprint = self.make_digest_fingerprint()
        self.descriptor = self.create_bridge_descriptor()
        self.dir_identity_response = self.create_dir_response()

        self.print_fingerprint()

        SocketServer.ThreadingTCPServer.__init__(self, config.listen_address, ORMITMHandler, bind_and_activate)

    def create_bridge_descriptor(self):
        nickname = self.config.nickname

        if not check_nickname(nickname):
            raise ORError("Bad nickname {}".format(nickname))

        published = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        bandwidth = "{:d} {:d} {:d}".format(self.config.announced_bandwidth[0], self.config.announced_bandwidth[1], 0)

        encoded_key = encodePEMRawRSAPubKey(self.identity_pubkey)
        encoded_onion_key = encodePEMRawRSAPubKey(self.onion_privkey)

        desc = DESCRIPTOR_TEMPLATE.format(
            nickname=nickname,
            address=self.config.address,
            port=self.config.listen_address[1],
            platform=PLATFORM,
            published=published,
            fingerprint=self.fingerprint,
            bandwidth=bandwidth,
            onion_key=encoded_onion_key,
            signing_key=encoded_key,
            ntor_onion_key=self.ntor_onion_key.public.encode("base64").strip())
        # Does it make sense for an MITM box to rotate its keys?

        router_signature = LowLevelSignature(self.identity_privkey).sign(SHA1.new(desc).digest())
        router_signature = PEM.encode(router_signature, "SIGNATURE")

        return desc + router_signature + "\n"

    def print_fingerprint(self):
        logging.info("Instance on {} has fingerprint {}".format(config.listen_address, self.fingerprint))

    def make_digest_fingerprint(self):
        pubkey = DerSequence([self.identity_pubkey.n, self.identity_pubkey.e]).encode()

        digest = SHA1.new(pubkey).hexdigest().upper()
        fingerprint = [digest[i*4:i*4+4] for i in range(HASH_LEN / 2)]

        return ' '.join(fingerprint)

    def create_dir_response(self):
        return DIR_IDENTITY_RESPONSE_TEMPLATE + self.descriptor

    def set_handler(self):
        if hasattr(self.config, "handler") and self.config.handler is not None:
            self.handler = self.config.handler
        else:
            import oregano.handler
            self.handler = oregano.handler.DefaultHandler

    def make_handler(self, link):
        return self.handler(link)

    def print_exc(self):
        exc = sys.exc_value
        exc_type = type(exc)

        if exc_type == ORError:
            logging.warning("A protocol error occurred: " + str(exc))
        elif exc_type == RuntimeError:
            logging.warning("A runtime error occurred: " + str(exc))
        elif not self.config.suppress_exceptions:
            logging.error("An exception occurred: " + traceback.format_exc())

class ORForwardingThread(threading.Thread):
    def __init__(self, request):
        threading.Thread.__init__(self)
        self.daemon = True
        self.request = request

    def run(self):
        try:
            self.process_or_conn()
        except Exception:
            self.request.server.print_exc()

        try:
            self.request.session.shutdown()
        except:
            pass

        self.request.session.close()

    def process_or_conn(self):
        while True:
            cell = self.request.server_or_conn.get_one_cell()
            self.request.handler.backward_cell_received(cell)

class ORMITMHandler(MITMHandler):
    def send_to_session(self, data):
        if self.server.config.use_length_hiding_with_client:
            send_range_safe(self.session, data, *self.server.config.padding_range_with_client)
        else:
            self.session.sendall(data)

    def send_to_remote(self, data):
        if self.server.config.use_length_hiding_with_server:
            send_range_safe(self.remote, data, *self.server.config.padding_range_with_server)
        else:
            self.remote.sendall(data)

    def or_handshake_with_client(self):
        self.client_or_conn = ORConnImpl(self.session, frozenset(self.server.config.versions_offered_to_client))

        self.client_or_conn.process_versions_cell(self.client_or_conn.get_one_cell())

        self.send_to_session(self.client_or_conn.versions_cell())

        self.send_to_session(self.client_or_conn.certs_cell([(1, self.server.encoded_cert), (2, self.server.encoded_cert)]))

        self.send_to_session(self.client_or_conn.auth_challenge_cell())

        self.send_to_session(self.client_or_conn.netinfo_cell(self.server.config.address, self.client_address[0]))

        self.client_or_conn.process_netinfo_cell(self.client_or_conn.get_one_cell())

    def or_handshake_with_server(self):
        self.server_or_conn = ORConnImpl(self.remote, frozenset(self.server.config.versions_offered_to_server))

        self.send_to_remote(self.server_or_conn.versions_cell())

        self.server_or_conn.process_versions_cell(self.server_or_conn.get_one_cell())

        certs_cell = self.server_or_conn.get_one_cell()

        if self.server.config.verify_server_certs:
            self.verify_server_certs(certs_cell)

        self.server_or_conn.process_auth_challenge_cell(self.server_or_conn.get_one_cell())

        self.server_or_conn.process_netinfo_cell(self.server_or_conn.get_one_cell())

        self.send_to_remote(self.server_or_conn.netinfo_cell(self.server.config.address, self.server.config.server_address[0]))

    def verify_server_certs(self, certs_cell):
        tls_link_cert = self.remote.peer_certificate.export(X509_FMT_DER)

        link_cert = None
        id_cert = None

        for type_num, cert in self.server_or_conn.parse_certs_cell(certs_cell):
            if type_num == 1:
                link_cert = cert

            if type_num == 2:
                id_cert = cert

        if not link_cert:
            raise ORError("Missing Link certificate in server CERTS cell")

        if not id_cert:
            raise ORError("Missing ID certificate in server CERTS cell")

        if link_cert != tls_link_cert:
            raise ORError("Link certificate in CERTS cell does not match TLS link certificate")

        try:
            self.remote.peer_certificate.check_issuer(X509Certificate(id_cert, format=X509_FMT_DER))
        except GNUTLSError:
            raise ORError("Link certificate is incorrectly signed")

        try:
            server_identity = RSA.import_key(id_cert)
        except (ValueError, IndexError, TypeError):
            raise ORError("Error in RSA key parsing")

        if self.server.config.server_fingerprint:
            server_fingerprint = self.server.config.server_fingerprint.strip().lower()

            server_key = DerSequence([server_identity.n, server_identity.e]).encode()

            remote_fingerprint = SHA1.new(server_key).hexdigest()

            if remote_fingerprint != server_fingerprint:
                raise ORError("Server ID certificate does not match the configured fingerprint: "
                    "expected {} but got {}".format(
                        server_fingerprint.upper(),
                        remote_fingerprint.upper()))

    def start_forwarding_thread(self):
        self.forwarding_thread = ORForwardingThread(self)
        self.forwarding_thread.start()

    def setup(self):
        self.handshake_with_client()

        if self.server.config.use_length_hiding_with_client and not self.session.can_use_length_hiding():
            raise RuntimeError("Can't use length hiding with client")

        self.or_handshake_with_client()

        try:
            self.build_server_connection()
        except (GNUTLSError, socket.error) as e:
            raise ORError("Could not connect to server: " + str(e))

        if self.server.config.use_length_hiding_with_server and not self.remote.can_use_length_hiding():
            raise RuntimeError("Can't use length hiding with server")

        self.or_handshake_with_server()

        self.circ_manager = CircuitManager(self.server_or_conn, self.client_or_conn)

        self.handler = self.server.make_handler(self)

        self.start_forwarding_thread()

    def handle(self):
        try:
            self.process_or_conn()
        except Exception:
            self.close_remote()
            raise

    def process_or_conn(self):
        while True:
            cell = self.client_or_conn.get_one_cell()
            self.handler.forward_cell_received(cell)

if __name__ == '__main__':
    from oregano.configuration import settings, default_settings

    logging.basicConfig(format="%(asctime)s thread-%(thread)d [%(levelname)s] %(message)s",
                        datefmt="%b %d %H:%M:%S",
                        level=logging.INFO)

    servers = []
    threads = []

    def sigint_received(signum, frame):
        for server in servers:
            server.shutdown()

    for key, setting in settings.items():
        config = MITMSettings(setting["server_address"], setting["listen_address"])
        config.__dict__.update(default_settings)
        config.__dict__.update(setting)

        server = ORMITMServer(config)

        logging.info("Starting listener on {} which forwards to {}".format(config.listen_address, config.server_address))

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True

        thread.start()

        servers.append(server)
        threads.append(thread)

    signal.signal(signal.SIGINT, sigint_received)

    try:
        while True:
            time.sleep(3600)
    except:
        pass