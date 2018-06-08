from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes

DH_MODULUS = bytes_to_long(
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
"49286651ECE65381FFFFFFFFFFFFFFFF".decode("hex"))
DH_MODULUS_MINUS_TWO = DH_MODULUS - 2
DH_GENERATOR = 2
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

        return long_to_bytes(public_int)

    def compute(self, public):
        secret_int = bytes_to_long(self.secret)

        public_int = bytes_to_long(public)

        if public_int < 2 or public_int > DH_MODULUS_MINUS_TWO:
            raise ValueError("Degenerate DH key")

        result = pow(public_int, secret_int, DH_MODULUS)

        return long_to_bytes(result)
