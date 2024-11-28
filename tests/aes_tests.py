import unittest
import os
from src.aes import Aes

class AesTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.aes = Aes(self.key)
        self.plaintext = b"Secret message"

    def test_encrypt_decrypt(self):
        iv, ciphertext, tag = self.aes.encrypt(self.plaintext)
        decrypted_message = self.aes.decrypt(iv, ciphertext, tag)
        self.assertEqual(decrypted_message, self.plaintext)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            Aes(os.urandom(16))

    def test_decrypt_invalid_tag(self):
        iv, ciphertext, tag = self.aes.encrypt(self.plaintext)

        invalid_tag = os.urandom(16)

        with self.assertRaises(Exception):
            self.aes.decrypt(iv, ciphertext, invalid_tag)

if __name__ == '__main__':
    unittest.main()
