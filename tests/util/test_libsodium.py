from synapse.util.libsodium import SignVerify


from .. import unittest


class LibsodiumUtilsTestCase(unittest.TestCase):
    def test_digital_signature(self) -> None:
        msg = "abc"
        signature = 'c09be8ad8b894cb05cf2e1ad3573680f85995636c083f9b564caa29905759d19735d63d503f3745ad3fa649ea2040fff32436f4bf5bfb172b4fcbff45b22f50b'
        publicKey = 'a4465fd76c16fcc458448076372abf1912cc5b150663a64dffefe550f96feadd'
        
        self.assertEqual(SignVerify(msg, signature, publicKey), True)
        self.assertEqual(SignVerify('aaa', signature, publicKey), False)