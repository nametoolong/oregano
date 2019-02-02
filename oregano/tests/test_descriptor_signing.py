import unittest

class RSAPrivateEncryptTest(unittest.TestCase):

    RSA_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC/NxXQNummsdEwTHqAYuCzwFHYIo2QWL9Ne5kw/2Fjl0NDKDhV
XwHTE2Z6oBJIM0k9eQApFOXkxlB7gTlSKBfqxRVCgIOZrQFINxswoCGiXoWEAnGa
Eorw3+iHKFPbAZs988gM2GcL/VzDExQn1tkQtwrPNabrX/q5+H4RgN5VxwIDAQAB
AoGAYYOoHi1C7v3T3rvB5WOHkGPN2VmVtD1uIgecUj6K3g0wAjmqsO7osUo9gt/L
MwLkoPLqQAkmTItOVA3Mu7cyqmfk+Hy0a6CkShF6SMdNfdDw49ut1TtPSqCYVszy
3n/GD9fHRqoJw6pe7jijDUYO3n298nqcjee87fIRJ3jwShECQQDXbDrJAalFDJjD
9FQjGZwc5/cIJAYfvzZiz4nK0t+SWZ1ZTq+/rMfuN/00MpWyqfEsIliqN7QjER81
5TPBYeKTAkEA4zuOTIa7QWXbyRcQrytPuWA8p5DuAGUyfDeOZea8otT8dXgyLWPW
P+5O90ZjNcEQxSnvk+nTvLbyObYRdw78fQJBALj3DdZvHbbS5QxDakalA5zyMvKD
c9qoZHsc9ZP30c0oMulunYp3QUcyPa8my9AXCKO7bePhZkNBvUmaXgDqGg8CQQCT
l/NtsXWfnNGNY/XqUW+PMPs0u+ZbS1/nXw6XEbAk88KnalLtOJPJIrkX1BhMqgKC
jiKXKKHnSc07vw7JDmrhAkBOwhR4PWeoIoH8agDE7naPfn31Ap+D0pYkvy2zdxix
o37efmlUVYDCvSW8mkS/FiZKmKhwk8btFRY8OlMebkkk
-----END RSA PRIVATE KEY-----'''

    EXPECTATIONS = {
        "":
'''-----BEGIN SIGNATURE-----
msDRF+bFpUol/rYbz+a/spuSserweDwn4/zz9VSZOITZLWS39zLoAfgpLw9Y3ry0
K6OqXZSTMJ4E7I8nh5/HF2whzYjnEIl9H1H2yO/ADt77HMtkiIH5eJsuECRthUpD
gkrqXJ2J5/l6H+DMQYeFDI2Y2B6nx+WpwHfV7m5ADz8=
-----END SIGNATURE-----''',
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
'''-----BEGIN SIGNATURE-----
kEh8Y1/6cGpiGAICUIBk3QVN6+EYfI99wsMmRlSUOWCPRZ3ijnip8iB4zl1D6lPR
A0iXdKRo6Z32PS0Avx7xQbsASiYSlGUc2ZRTZ6sGwDRuPh31Ukpmoc9hGXlo7ZHJ
Fq1CykSbkYcxzs4Ql1Jo0rOBggdoeYOrOcxI052atAg=
-----END SIGNATURE-----''',
        ''.join((chr(i) for i in xrange(0, 256))):
'''-----BEGIN SIGNATURE-----
fNIlUmL1LWfKveX3E1jJ8b8KNPlypTilGFmL+XkdzbYz3RI3fAx0UhkRFK9eNrkp
LPwpslZR8ZFZBwa+OFfruUhVkZw30suOlQyr2wjX9OBAHqSgXHw644q3KVL5r5nh
ZdiOxpIehWg7R9GEardNHqGJ68ycQ+X8zQp0kRH0+xc=
-----END SIGNATURE-----'''
    }

    def runTest(self):
        import base64
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from oregano.crypto import sign_router_descriptor

        key = serialization.load_pem_private_key(
            self.RSA_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )

        for item, value in self.EXPECTATIONS.items():
            self.assertEqual(value, sign_router_descriptor(key, item))
