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
        "": "SixKHniU4rXEtyBRu0dw+wfl+50ucroN1abRsjWMR14msJvl4NkrGIw/swwNPUz3z"
            "BRmMtWUO/N8GwYQe0Re8uMw41YrasIc6xTO/2FOthrCwsYglCebZ7BPjPfFokW8bY"
            "9x6KVnx9GxobBci+OqTePJ0cYxwdDfjiKEUkRDDkQ=",
        "\x00" * 20: "sovtiUnocFsXtrndWE1+K6fL/044ZnHY7pllk9WMejZiYcb+ZePjLoYR"
                     "nDouKMdlOBw+L9fA/zc2m1qFzzNEBHM1vkRE44R2GoaEbB95+TAaTl2p"
                     "zu5IRZUM94fio/q2AjxF4ScNEXG22LJDudR0r//plgK+Nd5MPtPrFBsz"
                     "1cs=",
        ''.join((chr(i) for i in xrange(1, 21))): "Uolkhx/lV94gJkOi1qJRiqdXM35"
                                                  "HPZUWK2Z+7/RMElI3+1wUZItqNE"
                                                  "vy8hDlZRJ+HNf3GTqfBFkHdmHVj"
                                                  "PBlhxOJ/PQTZU561nY5T9p4IbgQ"
                                                  "toAXhYQxoQYX8RNfgXhhhm3ZzlG"
                                                  "YR+wJOPPvHrAc5os4xbWIPJiTLm"
                                                  "0xxoDdylw="
    }

    def runTest(self):
        import base64
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from oregano.crypto import sign_raw_pkcs1

        key = serialization.load_pem_private_key(
            self.RSA_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )

        for item, value in self.EXPECTATIONS.items():
            self.assertEqual(base64.b64decode(value), sign_raw_pkcs1(key, item))
