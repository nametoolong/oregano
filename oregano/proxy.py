import collections
import signal
import SocketServer
import threading
import time

from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.connection import TLSContext, X509Credentials
from gnutls.constants import X509_FMT_DER

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

Date: {date}
Content-Type: application/octet-stream
Content-Encoding: identity
Expires: {expires}

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

        self.encoded_cert = open(self.config.cert).read()
        self.key = open(self.config.key).read()
        self.onion_secret_key = open(self.config.onion_secret_key).read()

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
        with self.logging_lock:
            print "Instance on {} has fingerprint {}".format(config.listen_address, self.fingerprint)

    def make_digest_fingerprint(self):
        pubkey = DerSequence([self.identity_pubkey.n, self.identity_pubkey.e]).encode()

        digest = SHA1.new(pubkey).hexdigest().upper()
        fingerprint = [digest[i*4:i*4+4] for i in range(HASH_LEN / 2)]

        return ' '.join(fingerprint)

    def create_dir_response(self):
        return DIR_IDENTITY_RESPONSE_TEMPLATE + self.descriptor

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
            circid, cell_content = self.request.server_or_conn.decode_circid(cell)

            command = cell_content[0]

            if command == COMMAND_RELAY or command == COMMAND_RELAY_EARLY:
                response_for_server, response_for_client = self.request.circ_manager.relay_backward(circid, cell_content)

                if response_for_server:
                    self.request.send_to_remote(response_for_server)

                if response_for_client:
                    self.request.send_to_session(response_for_client)

            elif command == COMMAND_CREATED_FAST:
                payload = cell_content[1:]

                response_for_server, response_for_client = self.request.circ_manager.created_fast(circid, payload)

                if response_for_server:
                    self.request.send_to_remote(response_for_server)

                if response_for_client:
                    self.request.send_to_session(response_for_client)

            elif command == COMMAND_DESTROY:
                circid_client = self.request.circ_manager.destroy_from_server(circid)

                if circid_client:
                    self.request.send_to_session(self.request.client_or_conn.add_circid(circid_client, cell_content))
            elif command == COMMAND_PADDING or command == COMMAND_VPADDING:
                self.request.send_to_session(self.request.client_or_conn.add_circid(0, cell_content))
            elif command == COMMAND_CREATED:
                # TODO: implement TAP handshake
                pass
            elif command == COMMAND_CREATED2:
                # TODO: implement ntor handshake
                pass
            else:
                with self.request.server.logging_lock:
                    print 'Received an unexpected cell: {}'.format(command.encode('hex'))

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
        self.client_or_conn = ORConnImpl(self.session)

        self.client_or_conn.process_versions_cell(self.client_or_conn.get_one_cell())

        self.send_to_session(self.client_or_conn.versions_cell())

        self.send_to_session(self.client_or_conn.certs_cell([(1, self.server.encoded_cert), (2, self.server.encoded_cert)]))

        self.send_to_session(self.client_or_conn.auth_challenge_cell())

        self.send_to_session(self.client_or_conn.netinfo_cell(self.server.config.address, self.client_address[0]))

        self.client_or_conn.process_netinfo_cell(self.client_or_conn.get_one_cell())

    def or_handshake_with_server(self):
        self.server_or_conn = ORConnImpl(self.remote)

        self.send_to_remote(self.server_or_conn.versions_cell())

        self.server_or_conn.process_versions_cell(self.server_or_conn.get_one_cell())

        certs_cell = self.server_or_conn.get_one_cell()

        if self.server.config.verify_server_certs:
            self.verify_server_certs(certs_cell)

        self.server_or_conn.process_auth_challenge_cell(self.server_or_conn.get_one_cell())

        self.server_or_conn.process_netinfo_cell(self.server_or_conn.get_one_cell())

        self.send_to_remote(self.server_or_conn.netinfo_cell(self.server.config.address, self.server.config.server_address[0]))

    def verify_server_certs(self, certs_cell):
        link_cert = self.remote.peer_certificate.export(X509_FMT_DER)

        certs = self.server_or_conn.parse_certs_cell(certs_cell)

        for type_num, cert in certs:
            # we can't run the full verification process
            # due to issues in python-gnutls
            # so do a simple and easy-to-spoof check
            # TODO: actual verification
            if type_num == 1:
                if not cert.startswith(link_cert):
                    raise ORError("Link certificate in CERTS cell does not match TLS link certificate")

            if type_num == 2 and self.server.config.server_fingerprint:
                server_fingerprint = self.server.config.server_fingerprint.strip().lower()

                server_identity = RSA.import_key(cert)
                server_key = DerSequence([server_identity.n, server_identity.e]).encode()

                if SHA1.new(server_key).hexdigest() != server_fingerprint:
                    raise ORError("Server ID certificate does not match the configured fingerprint")

    def start_forwarding_thread(self):
        self.forwarding_thread = ORForwardingThread(self)
        self.forwarding_thread.start()

    def setup(self):
        self.handshake_with_client()

        if self.server.config.use_length_hiding_with_client and not self.session.can_use_length_hiding():
            raise RuntimeError("Can't use length hiding with client")

        self.or_handshake_with_client()

        self.build_server_connection()

        if self.server.config.use_length_hiding_with_server and not self.remote.can_use_length_hiding():
            raise RuntimeError("Can't use length hiding with server")

        self.or_handshake_with_server()

        self.circ_manager = CircuitManager(self.server_or_conn, self.client_or_conn)

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
            circid, cell_content = self.client_or_conn.decode_circid(cell)

            command = cell_content[0]

            if command == COMMAND_RELAY or command == COMMAND_RELAY_EARLY:
                result = self.circ_manager.relay_forward(circid, cell_content)

                if result[0] == FINISHED:
                    response_for_client, response_for_server, = result[1:]

                    if response_for_client:
                        self.send_to_session(response_for_client)

                    if response_for_server:
                        self.send_to_remote(response_for_server)

                elif result[0] == INJECTED:
                    with self.circ_manager.lock:
                        streamid, circid, circid_server, = result[1:]

                        timestamp = time.time()
                        date = time.gmtime(timestamp)
                        expire_time = time.gmtime(timestamp + 60*60*24*365)

                        dir_response = self.server.dir_identity_response.format(
                                date=time.strftime("%a, %d %b %Y %H:%M:%S GMT", date),
                                expires=time.strftime("%a, %d %b %Y %H:%M:%S GMT", expire_time))

                        response_for_client, response_for_server = self.circ_manager.create_descriptor_response(
                            dir_response, circid, circid_server, streamid)

                        for response in response_for_client:
                            self.send_to_session(response)

                        for response in response_for_server:
                            self.send_to_remote(response)

            elif command == COMMAND_CREATE_FAST:
                payload = cell_content[1:]

                response, circid_server = self.circ_manager.create_fast(circid, payload)

                if response:
                    self.send_to_session(response)

                if circid_server:
                    self.send_to_remote(self.server_or_conn.add_circid(circid_server, cell_content))

            elif command == COMMAND_DESTROY:
                circid_server = self.circ_manager.destroy(circid)

                if circid_server:
                    self.send_to_remote(self.server_or_conn.add_circid(circid_server, cell_content))

            elif command == COMMAND_PADDING or command == COMMAND_VPADDING:
                self.send_to_remote(self.server_or_conn.add_circid(0, cell_content))

            elif command == COMMAND_CREATE:
                payload = cell_content[1:]

                response_for_client, response_for_server = self.circ_manager.create(circid, payload, self.server.onion_privkey)
                
                if response_for_client:
                    self.send_to_session(response_for_client)

                if response_for_server:
                    self.send_to_remote(response_for_server)

            elif command == COMMAND_CREATE2:
                payload = cell_content[1:]

                response_for_client, response_for_server = self.circ_manager.create2(circid, payload, self.server.ntor_onion_key)

                if response_for_client:
                    self.send_to_session(response_for_client)

                if response_for_server:
                    self.send_to_remote(response_for_server)

            elif command == COMMAND_PADDING_NEGOTIATE:
                if self.server_or_conn.version >= 5:
                    self.send_to_remote(self.server_or_conn.add_circid(0, cell_content))

            else:
                with self.server.logging_lock:
                    print 'Received an unexpected cell: {}'.format(command.encode('hex'))

if __name__ == '__main__':
    from oregano.configuration import settings, default_settings

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

        with server.logging_lock:
            print("Starting listener on {} which forwards to {}".format(config.listen_address, config.server_address))

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