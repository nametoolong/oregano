import unittest

class RSARawPublicEncodePEMTest(unittest.TestCase):

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

    RESULT = '''-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL83FdA26aax0TBMeoBi4LPAUdgijZBYv017mTD/YWOXQ0MoOFVfAdMT
ZnqgEkgzST15ACkU5eTGUHuBOVIoF+rFFUKAg5mtAUg3GzCgIaJehYQCcZoSivDf
6IcoU9sBmz3zyAzYZwv9XMMTFCfW2RC3Cs81putf+rn4fhGA3lXHAgMBAAE=
-----END RSA PUBLIC KEY-----'''

    def runTest(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from oregano.crypto import encode_raw_rsa_pubkey_pem

        key = serialization.load_pem_private_key(
            self.RSA_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )

        self.assertEqual(self.RESULT, encode_raw_rsa_pubkey_pem(key).strip())
