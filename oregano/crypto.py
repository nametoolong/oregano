import binascii
import os

import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameterNumbers,
    DHPublicNumbers
)
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import Hash, SHA1, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def make_random_bytes(length):
    return os.urandom(length)

_default_backend = cryptography.hazmat.backends.default_backend()

def bytes_to_long(bin_data):
    backend = _default_backend

    bn_ptr = backend._lib.BN_bin2bn(
        bin_data,
        len(bin_data),
        backend._ffi.NULL
    )
    backend.openssl_assert(bn_ptr != backend._ffi.NULL)

    return backend._bn_to_int(bn_ptr)

def hex_to_long(hex_data):
    backend = _default_backend

    bn_ptr = backend._ffi.new("BIGNUM **")
    bn_ptr[0] = backend._ffi.NULL
    res = backend._lib.BN_hex2bn(bn_ptr, hex_data)
    backend.openssl_assert(res != 0)
    backend.openssl_assert(bn_ptr[0] != backend._ffi.NULL)

    return backend._bn_to_int(bn_ptr[0])

def create_dh_parameter():
    DH_MODULUS = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" \
                 "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" \
                 "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" \
                 "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" \
                 "49286651ECE65381FFFFFFFFFFFFFFFF"
    DH_GENERATOR = 2

    return DHParameterNumbers(
        p=hex_to_long(DH_MODULUS),
        g=DH_GENERATOR
    )

DH_LEN = 128
DH_PARAM_NUMBERS = create_dh_parameter()
DH_PARAM = DH_PARAM_NUMBERS.parameters(_default_backend)

def sign_raw_pkcs1(key, data):
    backend = key._backend

    buf_size = backend._lib.RSA_size(key._rsa_cdata)
    backend.openssl_assert(buf_size > 0)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    res = backend._lib.RSA_private_encrypt(
        len(data),
        data,
        buf,
        key._rsa_cdata,
        backend._lib.RSA_PKCS1_PADDING
    )

    if res == -1:
        errors = backend._consume_errors()
        backend.openssl_assert(errors[0].lib == backend._lib.ERR_LIB_RSA)

        if (
            errors[0].reason ==
            backend._lib.RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE
        ):
            reason = "Data too long for key size."
        else:
            reason = "RSA_private_encrypt error."

        raise ValueError(reason)

    return backend._ffi.buffer(buf)[:buf_size]

def encode_raw_rsa_pubkey(key):
    if isinstance(key, RSAPrivateKey):
        public_key = key.public_key()
    elif isinstance(key, RSAPublicKey):
        public_key = key
    else:
        raise ValueError("encode_raw_rsa_pubkey requires a RSA key")

    return public_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)

def encode_raw_rsa_pubkey_pem(key):
    if isinstance(key, RSAPrivateKey):
        public_key = key.public_key()
    elif isinstance(key, RSAPublicKey):
        public_key = key
    else:
        raise ValueError("encode_raw_rsa_pubkey_pem requires a RSA key")

    return public_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1)

def pem_encode(data, marker):
    out = "-----BEGIN %s-----\n" % marker
    chunks = [binascii.b2a_base64(data[i:i + 48])
              for i in range(0, len(data), 48)]
    out += "".join(chunks)
    out += "-----END %s-----" % marker
    return out

def sign_router_descriptor(key, descriptor):
    hash_object = Hash(SHA1(), backend=_default_backend)
    hash_object.update(descriptor)
    return pem_encode(sign_raw_pkcs1(key, hash_object.finalize()), "SIGNATURE")

def pubkey_fingerprint(key):
    hash_object = Hash(SHA1(), backend=_default_backend)
    hash_object.update(encode_raw_rsa_pubkey(key))
    return binascii.hexlify(hash_object.finalize())

KEY_LEN = 16
HASH_LEN = 20

def kdf_tor(K0):
    backend = _default_backend

    K = ''
    i = 0

    while len(K) < 2 * KEY_LEN + 3 * HASH_LEN:
        hash_object = Hash(SHA1(), backend=backend)
        hash_object.update(K0 + chr(i))
        K += hash_object.finalize()
        i += 1

    return (K[:HASH_LEN],
            K[HASH_LEN:2*HASH_LEN],
            K[2*HASH_LEN:3*HASH_LEN],
            K[3*HASH_LEN:3*HASH_LEN+KEY_LEN],
            K[3*HASH_LEN+KEY_LEN:3*HASH_LEN+2*KEY_LEN])

PROTOID = b"ntor-curve25519-sha256-1"
M_EXPAND = PROTOID + b":key_expand"
T_MAC = PROTOID + b":mac"
T_KEY = PROTOID + b":key_extract"
T_VERIFY = PROTOID + b":verify"

def _hmac(key, msg):
    hmac_object = HMAC(
        key,
        SHA256(),
        backend=_default_backend
    )
    hmac_object.update(msg)
    return hmac_object.finalize()

def ntor_H(msg, tweak):
    return _hmac(key=tweak, msg=msg)

def ntor_H_mac(msg):
    return ntor_H(msg, T_MAC)

def ntor_H_verify(msg):
    return ntor_H(msg, T_VERIFY)

def kdf_ntor(key, length):
    hkdf_object = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=T_KEY,
        info=M_EXPAND,
        backend=_default_backend
    )
    return hkdf_object.derive(key)

PK_ENC_LEN = 128
PK_PAD_LEN = 42
TAP_C_HANDSHAKE_LEN = DH_LEN + KEY_LEN + PK_PAD_LEN

class EncodedDHPublicKey(object):

    __slots__ = ("public", )

    def __init__(self, privkey):
        backend = privkey._backend

        pub_key = backend._ffi.new("BIGNUM **")
        backend._lib.DH_get0_key(privkey._dh_cdata, pub_key, backend._ffi.NULL)
        backend.openssl_assert(pub_key[0] != backend._ffi.NULL)

        bn_num_bytes = backend._lib.BN_num_bytes(pub_key[0])
        bin_ptr = backend._ffi.new("unsigned char[]", bn_num_bytes)
        bin_len = backend._lib.BN_bn2bin(pub_key[0], bin_ptr)
        backend.openssl_assert(bin_len > 0)

        bin_data = backend._ffi.buffer(bin_ptr)[:bin_len]
        self.public = (DH_LEN - len(bin_data)) * b'\x00' + bin_data

def tap_handshake(payload, onion_key):
    pk_enc = payload[:PK_ENC_LEN]
    sym_enc = payload[PK_ENC_LEN:TAP_C_HANDSHAKE_LEN]

    decrypted = onion_key.decrypt(pk_enc, OAEP(MGF1(SHA1()), SHA1(), None))
    sym_key = decrypted[:KEY_LEN]
    dh_first_part = decrypted[KEY_LEN:PK_ENC_LEN]

    initial_counter = "\x00" * 16

    dh_second_part = Cipher(AES(sym_key), modes.CTR(initial_counter),
                            backend=_default_backend).decryptor().update(sym_enc)

    y = dh_first_part + dh_second_part

    privkey = DH_PARAM.generate_private_key()

    shared_key = privkey.exchange(
        DHPublicNumbers(bytes_to_long(y), DH_PARAM_NUMBERS).public_key(
            backend=_default_backend
        )
    )

    encoded_privkey = EncodedDHPublicKey(privkey)

    return (encoded_privkey, kdf_tor(shared_key))

NODE_ID_LENGTH = 20
G_LENGTH = 32
H_LENGTH = 32
KEYID_LENGTH = 32

class NTorKey(object):

    __slots__ = ("private", "auth")

    def __init__(self, secret=None):
        if secret:
            assert len(secret) == KEYID_LENGTH
            self.private = X25519PrivateKey.from_private_bytes(secret)
        else:
            self.private = X25519PrivateKey.generate()

    def get_public(self):
        return self.private.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

    def compute(self, public_bytes):
        public = X25519PublicKey.from_public_bytes(public_bytes)
        return self.private.exchange(public)

    def set_auth_value(self, auth):
        self.auth = auth

    def get_auth_value(self):
        return self.auth

def ntor_handshake(hdata, ntor_onion_key):
    node_id = hdata[:NODE_ID_LENGTH]
    keyid = hdata[NODE_ID_LENGTH:(NODE_ID_LENGTH + H_LENGTH)]

    if ntor_onion_key.public != keyid:
        raise ValueError("Mismatch KEYID from client")

    pubkey_X = hdata[(NODE_ID_LENGTH + H_LENGTH):(NODE_ID_LENGTH + H_LENGTH + G_LENGTH)]

    privkey = NTorKey()
    pubkey_Y = privkey.get_public()
    pubkey_B = ntor_onion_key.public

    xy = privkey.compute(pubkey_X)
    xb = NTorKey(ntor_onion_key.secret).compute(pubkey_X)

    # Node ID? We are an MITM box.
    secret_input = xy + xb + node_id + pubkey_B + pubkey_X + pubkey_Y + PROTOID

    verify = ntor_H_verify(secret_input)

    auth_input = verify + node_id + pubkey_B + pubkey_Y + pubkey_X + PROTOID + b"Server"

    privkey.set_auth_value(ntor_H_mac(auth_input))

    K = kdf_ntor(secret_input, 2*HASH_LEN+2*KEY_LEN)

    return (privkey, K)

def make_or_ciphers(key):
    backend = _default_backend

    Df = key[1]
    Db = key[2]
    Kf = key[3]
    Kb = key[4]

    initial_counter = "\x00" * 16
    Dffunc = Hash(SHA1(), backend=backend)
    Dbfunc = Hash(SHA1(), backend=backend)
    Kffunc = Cipher(AES(Kf), modes.CTR(initial_counter),
                    backend=_default_backend).encryptor()
    Kbfunc = Cipher(AES(Kb), modes.CTR(initial_counter),
                    backend=_default_backend).encryptor()

    Dffunc.update(Df)
    Dbfunc.update(Db)

    return (Dffunc, Dbfunc, Kffunc, Kbfunc)
