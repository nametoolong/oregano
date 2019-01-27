import binascii

from Crypto import Random
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.IO import PEM
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.asn1 import DerSequence
from Crypto.Util.number import ceil_div, bytes_to_long, long_to_bytes, size

from eccsnacks.curve25519 import scalarmult, scalarmult_base

DH_MODULUS = bytes_to_long(binascii.unhexlify(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF"))
DH_MODULUS_MINUS_TWO = DH_MODULUS - 2
DH_GENERATOR = 2
DH_LEN = 128
DH_SEC_LEN = 40

class DiffieHellman(object):
    '''
    Hand-rolled Diffie-Hellman implementation. Obviously we don't mind anything about security.
    '''

    __slots__ = ("secret", )

    def __init__(self, secret=None):
        if secret:
            assert len(secret) == DH_SEC_LEN
            self.secret = secret
        else:
            self.secret = Random.get_random_bytes(DH_SEC_LEN)

    def get_public(self):
        secret_int = bytes_to_long(self.secret)

        public_int = pow(DH_GENERATOR, secret_int, DH_MODULUS)

        return long_to_bytes(public_int, DH_LEN)

    def compute(self, public):
        secret_int = bytes_to_long(self.secret)

        public_int = bytes_to_long(public)

        if public_int < 2 or public_int > DH_MODULUS_MINUS_TWO:
            raise ValueError("Degenerate DH key")

        result = pow(public_int, secret_int, DH_MODULUS)

        return long_to_bytes(result, DH_LEN)

class LowLevelSignature(object):

    __slots__ = ("_key", )

    def __init__(self, key):
        self._key = key

    def sign(self, message):
        from Crypto.Util.py3compat import _copy_bytes

        modBits = size(self._key.n)
        k = ceil_div(modBits, 8)
        mLen = len(message)

        # Step 1
        if mLen > k - 11:
            raise ValueError("Plaintext is too long.")
        # Step 2a
        ps = b'\xff' * (k - mLen - 3)
        # Step 2b
        em = b'\x00\x01' + ps + b'\x00' + _copy_bytes(None, None, message)
        # Step 3a (OS2IP)
        em_int = bytes_to_long(em)
        # Step 3b (RSAEP)
        m_int = self._key._decrypt(em_int)
        # Step 3c (I2OSP)
        c = long_to_bytes(m_int, k)
        return c

def encode_raw_rsa_pubkey(key):
    return DerSequence([key.n, key.e]).encode()

def encode_raw_rsa_pubkey_pem(key):
    return PEM.encode(encode_raw_rsa_pubkey(key), "RSA PUBLIC KEY")

def sign_router_descriptor(key, descriptor):
    return PEM.encode(LowLevelSignature(key).sign(SHA1.new(descriptor).digest()), "SIGNATURE")

KEY_LEN = 16
HASH_LEN = 20

def kdf_tor(K0):
    K = ''
    i = 0

    while len(K) < 2 * KEY_LEN + 3 * HASH_LEN:
        K += SHA1.new(K0 + chr(i)).digest()
        i += 1

    return (K[:HASH_LEN], K[HASH_LEN:2*HASH_LEN], K[2*HASH_LEN:3*HASH_LEN],
            K[3*HASH_LEN:3*HASH_LEN+KEY_LEN], K[3*HASH_LEN+KEY_LEN:3*HASH_LEN+2*KEY_LEN])

KEYID_LENGTH = 32

PROTOID  = b"ntor-curve25519-sha256-1"
M_EXPAND = PROTOID + b":key_expand"
T_MAC    = PROTOID + b":mac"
T_KEY    = PROTOID + b":key_extract"
T_VERIFY = PROTOID + b":verify"

def _hmac(key, msg):
    h = HMAC.new(key, b"", digestmod=SHA256)
    h.update(msg)
    return h.digest()

def ntor_H(msg, tweak):
    return _hmac(key=tweak, msg=msg)

def ntor_H_mac(msg):
    return ntor_H(msg, T_MAC)

def ntor_H_verify(msg):
    return ntor_H(msg, tweak=T_VERIFY)

def bad_result(r):
    assert len(r) == 32
    return r == '\x00' * 32

def kdf_ntor(key, n):
    return HKDF(key, n, T_KEY, SHA256, context=M_EXPAND)

class NTorKey(object):

    __slots__ = ("secret", "auth")

    def __init__(self, secret=None):
        if secret:
            assert len(secret) == KEYID_LENGTH
            self.secret = secret
        else:
            self.secret = Random.get_random_bytes(KEYID_LENGTH)

    def get_public(self):
        return scalarmult_base(self.secret)

    def compute(self, public):
        result = scalarmult(self.secret, public)

        if bad_result(result):
            raise ValueError("Error computing Curve25519 shared secret")

        return result

    def set_auth_value(self, auth):
        self.auth = auth

    def get_auth_value(self):
        return self.auth
