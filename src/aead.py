from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad_message(msg: bytes) -> bytes:
    padding_len = AES.block_size - len(msg) % AES.block_size
    padding = bytes([padding_len] * padding_len)
    return msg + padding

def unpad_message(padded_message: bytes) -> bytes:
    padding_len = padded_message[-1]
    return padded_message[:-padding_len]

def encrypt_msg(key: bytes, msg: bytes) -> tuple[bytes, bytes]:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad_message(msg)
    encrypted_message = cipher.encrypt(padded_message)
    return iv, encrypted_message

def decrypt_msg(key: bytes, iv: bytes, enc_msg: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decr_msg = cipher.decrypt(enc_msg) 
    return unpad_message(decr_msg)

if __name__ == '__main__':
    pass