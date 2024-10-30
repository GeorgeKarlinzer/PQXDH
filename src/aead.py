from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from abc import ABC, abstractmethod

class Aead(ABC):
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long for AES-256.")
        self.key = key

    @abstractmethod
    def encrypt(self, plaintext: bytes):
        pass

    @abstractmethod
    def decrypt(self, iv: bytes, ciphertext: bytes, tag: bytes):
        pass

class Aes(Aead):
    def encrypt(self, plaintext: bytes):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    def decrypt(self, iv: bytes, ciphertext: bytes, tag: bytes):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
if __name__ == '__main__':
    pass