import socket
import struct
import random
import threading
import time

from oregano.crypto import (
    KEY_LEN,
    HASH_LEN,

    EncodedDHPublicKey,
    NTorKey,

    tap_handshake,
    ntor_handshake,

    kdf_tor,
    make_or_ciphers,
    make_random_bytes
)

COMMAND_PADDING = "\x00"
COMMAND_CREATE = "\x01"
COMMAND_CREATED = "\x02"
COMMAND_RELAY = "\x03"
COMMAND_DESTROY = "\x04"
COMMAND_CREATE_FAST = "\x05"
COMMAND_CREATED_FAST = "\x06"
COMMAND_VERSIONS = "\x07"
COMMAND_NETINFO = "\x08"
COMMAND_RELAY_EARLY = "\x09"
COMMAND_CREATE2 = "\x0a"
COMMAND_CREATED2 = "\x0b"
COMMAND_PADDING_NEGOTIATE = "\x0c"
COMMAND_VPADDING = "\x80"
COMMAND_CERTS = "\x81"
COMMAND_AUTH_CHALLENGE = "\x82"

ERROR_PROTOCOL = "\x01"
ERROR_RESOURCELIMIT = "\x05"
ERROR_FINISHED = "\x09"
ERROR_DESTROYED = "\x0b"

RELAY_DATA = "\x02"
RELAY_END = "\x03"
RELAY_CONNECTED = "\x04"
RELAY_BEGIN_DIR = "\x0d"

REASON_DONE = "\x06"

PAYLOAD_LEN = 509
MAX_DATA_LEN = PAYLOAD_LEN - 11

FINISHED = 0
INJECTED = 1

GET_AUTHORITY_Z = "GET /tor/server/authority.z "

class ORError(Exception):
    pass

class CircuitKey(object):
    __slots__ = ("our_material", "KH", "Dffunc", "Dbfunc", "Kffunc", "Kbfunc", "dir_streams")

    def __init__(self, *args):
        self.our_material, self.KH, self.Dffunc, self.Dbfunc, self.Kffunc, self.Kbfunc = args
        self.dir_streams = None

    def add_dir_stream(self, streamid):
        if not self.dir_streams:
            self.dir_streams = {}

        self.dir_streams[streamid] = 0

    def has_dir_stream(self, streamid):
        if not self.dir_streams:
            return False

        return streamid in self.dir_streams

    def mark_dir_stream_as_connected(self, streamid):
        self.dir_streams[streamid] = 1

    def has_dir_stream_connected(self, streamid):
        if not self.dir_streams or streamid not in self.dir_streams:
            return False

        return self.dir_streams[streamid] == 1

def check_nickname(nickname):
    return nickname.isalnum() and (1 <= len(nickname) <= 19)

def cell_is_var_length(command):
    return command == COMMAND_VERSIONS or command >= "\x80"

class ORConnImpl:

    supported_versions = frozenset((3, 4, 5))

    def __init__(self, conn, our_versions):
        self.conn = conn
        self.buf = ''

        self.circid_len = 0
        self.version = 0

        self.our_versions = self.supported_versions & our_versions

    def read_from_conn(self):
        data = self.conn.recv(4096)

        if not data:
            raise ORError("Connection is closed")

        self.buf += data

    def get_one_cell(self):
        if not self.circid_len:
            circid_len = 2
        else:
            circid_len = self.circid_len

        while len(self.buf) < circid_len + 1:
            self.read_from_conn()

        command = self.buf[circid_len]

        if cell_is_var_length(command):
            while len(self.buf) < circid_len + 3:
                self.read_from_conn()

            length = struct.unpack("!H", self.buf[circid_len+1:circid_len+3])[0]

            while len(self.buf) < circid_len + 3 + length:
                self.read_from_conn()

            cell = self.buf[:circid_len+length+3]
            self.buf = self.buf[circid_len+length+3:]

        else:
            length = PAYLOAD_LEN

            while len(self.buf) < circid_len + 1 + length:
                self.read_from_conn()

            cell = self.buf[:circid_len+length+1]
            self.buf = self.buf[circid_len+length+1:]

        return cell

    def decode_circid(self, cell):
        if not self.circid_len:
            circid_len = 2
        else:
            circid_len = self.circid_len

        if circid_len == 2:
            circid = struct.unpack("!H", cell[:circid_len])[0]
        elif circid_len == 4:
            circid = struct.unpack("!I", cell[:circid_len])[0]
        else:
            raise ORError("Unsupported CircID length")

        cell_content = cell[circid_len:]

        return (circid, cell_content)

    def process_versions_cell(self, versions_cell):
        versions = self.parse_versions_cell(versions_cell)

        common_versions = set(versions) & self.our_versions

        if not common_versions:
            raise ORError("Unable to negotiate a common version")

        self.version = max(common_versions)

        if self.version >= 4:
            self.circid_len = 4
        else:
            self.circid_len = 2

    def parse_versions_cell(self, cell):
        circid, cell_content = self.decode_circid(cell)

        if circid != 0 or cell_content[0] != COMMAND_VERSIONS:
            raise ORError("Malformed VERSIONS cell")

        cell_content = cell_content[3:]

        if len(cell_content) % 2 != 0:
            raise ORError("Malformed VERSIONS cell")

        versions = []

        for i in range(len(cell_content) / 2):
            versions.append(struct.unpack("!H", cell_content[i*2:i*2+2])[0])

        return versions

    def parse_certs_cell(self, cell):
        circid, cell_content = self.decode_circid(cell)

        if circid != 0 or cell_content[0] != COMMAND_CERTS:
            raise ORError("Malformed CERTS cell")

        cert_num = struct.unpack("!B", cell_content[3])[0]
        cell_content = cell_content[4:]
        certs = []

        for _ in range(cert_num):
            if len(cell_content) < 3:
                raise ORError("Malformed CERTS cell")

            cert_type = struct.unpack("!B", cell_content[0])[0]
            length = struct.unpack("!H", cell_content[1:3])[0]

            if len(cell_content) < length+3:
                raise ORError("Malformed CERTS cell")

            certs.append((cert_type, cell_content[3:length+3]))

            cell_content = cell_content[length+3:]

        return certs

    def process_auth_challenge_cell(self, auth_challenge_cell):
        # TODO: actual decoding and parsing
        circid, cell_content = self.decode_circid(auth_challenge_cell)

        if circid != 0 or cell_content[0] != COMMAND_AUTH_CHALLENGE:
            raise ORError("Malformed AUTH_CHALLENGE cell")

    def process_netinfo_cell(self, netinfo_cell):
        # TODO: actual decoding and parsing
        circid, cell_content = self.decode_circid(netinfo_cell)

        if circid != 0 or cell_content[0] != COMMAND_NETINFO:
            raise ORError("Malformed NETINFO cell")



    def add_circid(self, circid, content):
        if self.circid_len == 2:
            packed_circid = struct.pack("!H", circid)
        elif self.circid_len == 4:
            packed_circid = struct.pack("!I", circid)
        else:
            raise ORError("Unsupported CircID length")

        return packed_circid + content

    def versions_cell(self):
        payload = ''.join([struct.pack("!H", version_num)
                           for version_num in sorted(self.our_versions)])

        return "\x00" * 2 + COMMAND_VERSIONS + struct.pack("!H", len(payload)) + payload

    def certs_cell(self, certs):
        cell_content = []

        cell_content.append(struct.pack("!B", len(certs)))

        for type_num, encoded_cert in certs:
            cell_content.append(struct.pack("!B", type_num))
            cell_content.append(struct.pack("!H", len(encoded_cert)))
            cell_content.append(encoded_cert)

        payload = ''.join(cell_content)

        return self.add_circid(0, COMMAND_CERTS + struct.pack("!H", len(payload)) + payload)

    def auth_challenge_cell(self):
        payload = "\x00" * 32 + "\x00\x00"

        return self.add_circid(
            0,
            COMMAND_AUTH_CHALLENGE + struct.pack("!H", len(payload)) + payload)

    def encode_address(self, address):
        try:
            return "\x04\x04" + socket.inet_aton(address)
        except Exception:
            return "\xf1\x00"

    def netinfo_cell(self, our_addr, remote_addr):
        payload = struct.pack("!I", int(time.time()))
        payload += self.encode_address(remote_addr)
        payload += "\x01"
        payload += self.encode_address(our_addr)
        payload += "\x00" * (PAYLOAD_LEN - len(payload))
        return self.add_circid(0, COMMAND_NETINFO + payload)

    def destroy_cell(self, circid, reason):
        payload = reason + "\x00" * (PAYLOAD_LEN - len(reason))
        return self.add_circid(circid, COMMAND_DESTROY + payload)

    def create_fast_cell(self, circid, content):
        payload = content + "\x00" * (PAYLOAD_LEN - len(content))
        return self.add_circid(circid, COMMAND_CREATE_FAST + payload)

    def created_fast_cell(self, circid, content):
        payload = content + "\x00" * (PAYLOAD_LEN - len(content))
        return self.add_circid(circid, COMMAND_CREATED_FAST + payload)

    def created_cell(self, circid, content):
        payload = content + "\x00" * (PAYLOAD_LEN - len(content))
        return self.add_circid(circid, COMMAND_CREATED + payload)

    def created2_cell(self, circid, content):
        payload = content + "\x00" * (PAYLOAD_LEN - len(content))
        return self.add_circid(circid, COMMAND_CREATED2 + payload)

    def relay_cell(self, circid, payload):
        return self.add_circid(circid, COMMAND_RELAY + payload)

    def relay_early_cell(self, circid, payload):
        return self.add_circid(circid, COMMAND_RELAY_EARLY + payload)

    def padding_cell(self, payload):
        return self.add_circid(0, COMMAND_PADDING + payload)

    def padding_negotiate_cell(self, payload):
        return self.add_circid(0, COMMAND_PADDING_NEGOTIATE + payload)

    def vpadding_cell(self, payload):
        return self.add_circid(0, COMMAND_VPADDING + struct.pack("!H", len(payload)) + payload)

def encrypt_onion_skin(content_no_digest, key, direction='f'):
    if direction == 'f':
        Dfunc = key.Dffunc
        Kfunc = key.Kffunc
    elif direction == 'b':
        Dfunc = key.Dbfunc
        Kfunc = key.Kbfunc
    else:
        raise ORError("Unrecognized direction {}".format(direction))

    Dfunc.update(content_no_digest)
    temp_Dfunc = Dfunc.copy()
    digest = temp_Dfunc.finalize()[:4]
    content = content_no_digest[0:5] + digest + content_no_digest[9:]
    payload = Kfunc.update(content)

    return payload

def build_relay_cell(streamid, data, command=RELAY_DATA):
    content_unpadded = ''.join((command, "\x00\x00", struct.pack("!H", streamid),
                                "\x00\x00\x00\x00", struct.pack("!H", len(data)), data))
    content_no_digest = content_unpadded + "\x00" * (PAYLOAD_LEN - len(content_unpadded))

    return content_no_digest

class CircuitManager:

    MAX_CIRCUITS_PER_CLIENT = 100

    def __init__(self, server_or_conn, client_or_conn):
        self.server_or_conn = server_or_conn
        self.client_or_conn = client_or_conn

        self.lock = threading.RLock()

        self.circuits_client = {} # circid -> key map
        self.circuits_server = {} # circid -> key map
        self.map_client_to_server = {} # circid -> circid map
        self.map_server_to_client = {} # circid -> circid map

    def create_circid_for_server(self):
        circid_len = self.server_or_conn.circid_len

        if circid_len == 2:
            circid = random.getrandbits(16)

            while circid in self.circuits_server:
                circid = random.getrandbits(16)

        elif circid_len == 4:
            circid = random.getrandbits(31) | 0x80000000

            while circid in self.circuits_server:
                circid = random.getrandbits(31) | 0x80000000

        return circid

    def create_fast(self, circid, payload):
        if circid == 0:
            return (None, 0)

        if len(self.circuits_client) >= self.MAX_CIRCUITS_PER_CLIENT:
            return (self.client_or_conn.destroy_cell(circid, ERROR_RESOURCELIMIT), 0)

        X = payload[:HASH_LEN]
        Y = make_random_bytes(HASH_LEN)

        key = kdf_tor(X + Y)

        ciphers = make_or_ciphers(key)

        with self.lock:
            if circid in self.circuits_client:
                return (None, 0)

            circid_server = self.create_circid_for_server()

            self.circuits_client[circid] = CircuitKey(Y, key[0], *ciphers)
            self.circuits_server[circid_server] = CircuitKey(X, None, None, None, None, None)

            self.map_client_to_server[circid] = circid_server
            self.map_server_to_client[circid_server] = circid

        return (None, circid_server)

    def create(self, circid, payload, onion_key):
        if circid == 0:
            return (None, None)

        if len(self.circuits_client) >= self.MAX_CIRCUITS_PER_CLIENT:
            return (self.client_or_conn.destroy_cell(circid, ERROR_RESOURCELIMIT), None)

        try:
            privkey, key = tap_handshake(payload, onion_key)
        except ValueError:
            return (self.client_or_conn.destroy_cell(circid, ERROR_PROTOCOL), None)

        ciphers = make_or_ciphers(key)

        X = make_random_bytes(HASH_LEN)

        with self.lock:
            if circid in self.circuits_client:
                return (None, None)

            circid_server = self.create_circid_for_server()

            self.circuits_client[circid] = CircuitKey(privkey, key[0], *ciphers)
            self.circuits_server[circid_server] = CircuitKey(X, None, None, None, None, None)

            self.map_client_to_server[circid] = circid_server
            self.map_server_to_client[circid_server] = circid

        return (None, self.server_or_conn.create_fast_cell(circid_server, X))

    def create2(self, circid, payload, ntor_onion_key):
        if circid == 0:
            return (None, None)

        if len(self.circuits_client) >= self.MAX_CIRCUITS_PER_CLIENT:
            return (self.client_or_conn.destroy_cell(circid, ERROR_RESOURCELIMIT), None)

        htype = struct.unpack("!H", payload[:2])[0]
        hlen = struct.unpack("!H", payload[2:4])[0]

        # HTYPE = 2 is ntor
        if htype != 2 or len(payload) < hlen + 4:
            return (self.client_or_conn.destroy_cell(circid, ERROR_PROTOCOL), None)

        hdata = payload[4:4+hlen]

        try:
            privkey, K = ntor_handshake(hdata, ntor_onion_key)
        except ValueError:
            return (self.client_or_conn.destroy_cell(circid, ERROR_PROTOCOL), None)

        ciphers = make_or_ciphers((None, K[:HASH_LEN], K[HASH_LEN:2*HASH_LEN],
                                   K[2*HASH_LEN:2*HASH_LEN+KEY_LEN],
                                   K[2*HASH_LEN+KEY_LEN:2*HASH_LEN+2*KEY_LEN]))

        X = make_random_bytes(HASH_LEN)

        with self.lock:
            if circid in self.circuits_client:
                return (None, None)

            circid_server = self.create_circid_for_server()

            self.circuits_client[circid] = CircuitKey(privkey, None, *ciphers)
            self.circuits_server[circid_server] = CircuitKey(X, None, None, None, None, None)

            self.map_client_to_server[circid] = circid_server
            self.map_server_to_client[circid_server] = circid

        return (None, self.server_or_conn.create_fast_cell(circid_server, X))

    def created_fast(self, circid, payload):
        if circid not in self.circuits_server:
            return (self.server_or_conn.destroy_cell(circid, ERROR_FINISHED), None)

        if circid not in self.map_server_to_client:
            self.destroy_from_server(circid)
            return (self.server_or_conn.destroy_cell(circid, ERROR_FINISHED), None)

        circid_client = self.map_server_to_client[circid]

        X = self.circuits_server[circid].our_material
        Y = payload[:HASH_LEN]
        KH = payload[HASH_LEN:2*HASH_LEN]

        key = kdf_tor(X + Y)

        ciphers = make_or_ciphers(key)

        if key[0] != KH:
            return (self.server_or_conn.destroy_cell(circid, ERROR_PROTOCOL),
                    self.client_or_conn.destroy_cell(circid_client, ERROR_DESTROYED))

        with self.lock:
            self.circuits_server[circid] = CircuitKey(X, key[0], *ciphers)

            if circid_client not in self.circuits_client:
                self.destroy_from_server(circid)
                return (self.server_or_conn.destroy_cell(circid, ERROR_FINISHED), None)

            key_client = self.circuits_client[circid_client]

            if isinstance(key_client.our_material, EncodedDHPublicKey):
                client_Y = key_client.our_material.public
                client_KH = key_client.KH
                return (
                    None,
                    self.client_or_conn.created_cell(
                        circid_client,
                        client_Y + client_KH
                    )
                )
            elif isinstance(key_client.our_material, NTorKey):
                client_Y = key_client.our_material.get_public()
                client_auth = key_client.our_material.get_auth_value()
                hs_data = client_Y + client_auth
                hs_len = struct.pack("!H", len(hs_data))
                return (
                    None,
                    self.client_or_conn.created2_cell(
                        circid_client,
                        hs_len + hs_data
                    )
                )
            elif isinstance(key_client.our_material, basestring):
                client_Y = key_client.our_material
                client_KH = key_client.KH
                return (
                    None,
                    self.client_or_conn.created_fast_cell(
                        circid_client,
                        client_Y + client_KH
                    )
                )
            else:
                raise RuntimeError("Impossible key type")

        assert False, "Impossible execution path in created_fast()"

    def destroy(self, circid):
        with self.lock:
            if circid in self.circuits_client:
                del self.circuits_client[circid]

            if circid in self.map_client_to_server:
                circid_server = self.map_client_to_server[circid]

                if circid_server in self.circuits_server:
                    del self.circuits_server[circid_server]

                if circid_server in self.map_server_to_client:
                    del self.map_server_to_client[circid_server]

                del self.map_client_to_server[circid]

                return circid_server

            return 0

    def destroy_from_server(self, circid):
        with self.lock:
            if circid in self.circuits_server:
                del self.circuits_server[circid]

            if circid in self.map_server_to_client:
                circid_client = self.map_server_to_client[circid]

                if circid_client in self.circuits_client:
                    del self.circuits_client[circid_client]

                if circid_client in self.map_client_to_server:
                    del self.map_client_to_server[circid_client]

                del self.map_server_to_client[circid]

                return circid_client

            return 0

    def relay_forward(self, circid, cell_content):
        with self.lock:
            if circid not in self.circuits_client:
                return (FINISHED, self.client_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            if circid not in self.map_client_to_server:
                self.destroy(circid)
                return (FINISHED, self.client_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            circid_server = self.map_client_to_server[circid]

            if circid_server not in self.circuits_server:
                self.destroy(circid)
                return (FINISHED, self.client_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            key_client = self.circuits_client[circid]
            key_server = self.circuits_server[circid_server]

        command = cell_content[0]
        payload = cell_content[1:]

        content = key_client.Kffunc.update(payload)

        if content[1:3] != "\x00\x00": # not recognized
            new_payload = key_server.Kffunc.update(content)
            return (FINISHED,
                    None,
                    self.server_or_conn.add_circid(
                        circid_server,
                        command + new_payload
                    ))

        temp_Dffunc = key_client.Dffunc.copy()

        cell_digest = content[5:9]
        content_no_digest = content[0:5] + "\x00\x00\x00\x00" + content[9:]

        temp_Dffunc.update(content_no_digest)
        finalizing_Dffunc = temp_Dffunc.copy()
        computed_digest = finalizing_Dffunc.finalize()[:4]

        if cell_digest == computed_digest: # recognized
            key_client.Dffunc = temp_Dffunc

            streamid = struct.unpack("!H", content[3:5])[0]

            if content[0] == RELAY_DATA and key_client.has_dir_stream(streamid):
                length = struct.unpack("!H", content[9:11])[0]

                if length > MAX_DATA_LEN:
                    raise ORError("Incorrect length in RELAY cell")

                data = content[11:11+length]

                if data.startswith(GET_AUTHORITY_Z): # a quick and dirty way
                    return (INJECTED, streamid, circid, circid_server)

            elif content[0] == RELAY_BEGIN_DIR:
                key_client.add_dir_stream(streamid)

            new_payload = encrypt_onion_skin(content_no_digest, key_server, direction='f')
            return (FINISHED,
                    None,
                    self.server_or_conn.add_circid(
                        circid_server,
                        command + new_payload
                    ))
        else:
            new_payload = key_server.Kffunc.update(content)
            return (FINISHED,
                    None,
                    self.server_or_conn.add_circid(
                        circid_server,
                        command + new_payload
                    ))

    def relay_backward(self, circid, cell_content):
        with self.lock:
            if circid not in self.circuits_server:
                return (self.server_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            if circid not in self.map_server_to_client:
                self.destroy_from_server(circid)
                return (self.server_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            circid_client = self.map_server_to_client[circid]

            if circid_client not in self.circuits_client:
                self.destroy_from_server(circid)
                return (self.server_or_conn.destroy_cell(circid, ERROR_DESTROYED), None)

            key_client = self.circuits_client[circid_client]
            key_server = self.circuits_server[circid]

        command = cell_content[0]
        payload = cell_content[1:]

        content = key_server.Kbfunc.update(payload)

        if content[1:3] != "\x00\x00": # not recognized
            new_payload = key_client.Kbfunc.update(content)
            return (None, self.client_or_conn.add_circid(circid_client, command + new_payload))

        temp_Dbfunc = key_server.Dbfunc.copy()

        cell_digest = content[5:9]
        content_no_digest = content[0:5] + "\x00\x00\x00\x00" + content[9:]

        temp_Dbfunc.update(content_no_digest)
        finalizing_Dbfunc = temp_Dbfunc.copy()
        computed_digest = finalizing_Dbfunc.finalize()[:4]

        if cell_digest == computed_digest: # recognized
            key_server.Dbfunc = temp_Dbfunc

            streamid = struct.unpack("!H", content[3:5])[0]

            if content[0] == RELAY_CONNECTED and key_client.has_dir_stream(streamid):
                if key_client.has_dir_stream_connected(streamid):
                    return (None, None)
                else:
                    key_client.mark_dir_stream_as_connected(streamid)

            new_payload = encrypt_onion_skin(content_no_digest, key_client, direction='b')
            return (None, self.client_or_conn.add_circid(circid_client, command + new_payload))
        else:
            new_payload = key_client.Kbfunc.update(content)
            return (None, self.client_or_conn.add_circid(circid_client, command + new_payload))

    def create_descriptor_response(self, descriptor, circid, circid_server, streamid):
        with self.lock:
            if circid in self.circuits_client:
                key_client = self.circuits_client[circid]
                stream_connected = key_client.has_dir_stream_connected(streamid)
                key_client.mark_dir_stream_as_connected(streamid)
            else:
                key_client = None

            if circid_server in self.circuits_server:
                key_server = self.circuits_server[circid_server]
            else:
                key_server = None

        data = []

        while descriptor:
            cell_data, descriptor = descriptor[0:MAX_DATA_LEN], descriptor[MAX_DATA_LEN:]
            data.append(cell_data)

        if key_client:
            cells_for_client = []

            if not stream_connected:
                cells_for_client.append(
                    self.client_or_conn.relay_cell(
                        circid,
                        encrypt_onion_skin(
                            build_relay_cell(streamid, '', command=RELAY_CONNECTED),
                            key_client,
                            direction='b'
                        )
                    )
                )

            cells_for_client.extend(
                [self.client_or_conn.relay_cell(
                    circid,
                    encrypt_onion_skin(
                        build_relay_cell(streamid, cell_data),
                        key_client,
                        direction='b'
                    ))
                 for cell_data in data]
            )

            cells_for_client.append(
                self.client_or_conn.relay_cell(
                    circid,
                    encrypt_onion_skin(
                        build_relay_cell(streamid, REASON_DONE, command=RELAY_END),
                        key_client,
                        direction='b'
                    )
                )
            )

        else:
            cells_for_client = ()

        if key_server:
            cells_for_server = (
                self.server_or_conn.relay_cell(
                    circid_server,
                    encrypt_onion_skin(
                        build_relay_cell(streamid, REASON_DONE, command=RELAY_END),
                        key_server,
                        direction='f'
                    )
                ),
            )
        else:
            cells_for_server = ()

        return (cells_for_client, cells_for_server)
