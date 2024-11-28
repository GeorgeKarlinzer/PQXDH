from dilithium_py.dilithium import Dilithium3
from kyber import Kyber512
from KeysBundle import KeyPair, KeysBundle
from InitMessage import InitMessage
from aes import decrypt_msg

class Receiver():
    def __init__(self, sk: bytes) -> None:
        self.sk = sk
        self.ots: list[KeyPair] = []
        self.generate_last_resort()
        self.generate_one_time_keys()

    def generate_last_resort(self):
        lr_pk, lr_sk = Kyber512.keygen()
        lr_pk_sig = self.sign(lr_pk)
        self.lr = KeyPair(lr_pk, lr_sk, lr_pk_sig)

    def generate_one_time_keys(self, amount = 5):
        for _ in range(amount):
            ot_pk, ot_sk = Kyber512.keygen()
            ot_pk_sig = self.sign(ot_pk)
            ot = KeyPair(ot_pk, ot_sk, ot_pk_sig)
            self.ots.append(ot)

    def sign(self, m: bytes) -> bytes:
        sig = Dilithium3.sign(self.sk, m)
        return sig
    
    def get_key_bundle(self) -> KeysBundle:
        return KeysBundle(self.lr.key, [x.key for x in self.ots])
    
    def receive_init_msg(self, sndr_ik: bytes, init_msg: InitMessage) -> str:
        # get used key
        key_id = init_msg.key_id
        keys = self.ots + [self.lr]
        key = next((key for key in keys if key.key.id == key_id))

        # get aes key
        k = Kyber512.dec(init_msg.c, key.sk)

        # decrypt message
        msg = decrypt_msg(k, init_msg.iv, init_msg.enc_msg)

        # verify message signature
        if not Dilithium3.verify(sndr_ik, msg, init_msg.msg_sig):
            raise Exception("Signature verification failed.")

        return msg