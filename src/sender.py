import random
from dilithium_py.dilithium import Dilithium3
from kyber import Kyber512
from InitMessage import InitMessage
from KeysBundle import Key, KeysBundle
from aead import encrypt_msg


def construct_init_msg(sndr_id_sk: bytes, rsvr_ik: bytes, rsvr_bundle: KeysBundle, msg: bytes) -> InitMessage:
    # verify signature
    verify_bundle(rsvr_ik, rsvr_bundle)

    # get kyber key
    key: Key
    if len(rsvr_bundle.ots) > 0:
        key = random.choice(rsvr_bundle.ots)
    else:
        key = rsvr_bundle.lr_key

    # sign msg
    msg_sig = Dilithium3.sign(sndr_id_sk, msg)

    # generate shared key
    c, k = Kyber512.enc(key.key)

    # encrypt message
    iv, enc_msg = encrypt_msg(k, msg)

    # construct inital message
    init_msg = InitMessage(key.id, c, enc_msg, iv, msg_sig)

    return init_msg


def verify_bundle(rsv_ik: bytes, bundle: KeysBundle) -> None:
    # verify last resort key signature
    verify_sig(rsv_ik, bundle.lr)

    # verify one time keys signatures
    for ot in bundle.ots:
        verify_sig(rsv_ik, ot)

def verify_sig(ik: bytes, key: Key) -> None:
    if not Dilithium3.verify(ik, key.key, key.sig):
        raise Exception("Signature verification failed.")