import uuid


class InitMessage:
    def __init__(self, key_id: uuid, c: bytes, enc_msg: bytes, iv: bytes, msg_sig: bytes) -> None:
        self.key_id = key_id
        self.c = c
        self.enc_msg = enc_msg
        self.iv = iv
        self.msg_sig = msg_sig
