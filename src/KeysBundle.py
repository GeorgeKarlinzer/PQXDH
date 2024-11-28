import uuid

class Key:
    def __init__(self, key: bytes, sig: bytes) -> None:
        self.key = key
        self.sig = sig
        self.id = uuid.uuid4()

class KeyPair:
    def __init__(self, pk: bytes, sk: bytes, pk_sig: bytes) -> None:
        self.sk = sk
        self.key = Key(pk, pk_sig)
        

class KeysBundle:
    def __init__(self, lr: Key, ots: list[Key]):
        self.lr = lr
        self.ots = ots