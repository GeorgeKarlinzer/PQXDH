# serialization.py
import base64
import uuid

from KeysBundle import Key, KeysBundle
from InitMessage import InitMessage

def key_to_dict(k: Key) -> dict:
    return {
        "key": base64.b64encode(k.key).decode("utf-8"),
        "sig": base64.b64encode(k.sig).decode("utf-8"),
        "id": str(k.id),  # convert UUID object to string
    }

def dict_to_key(d: dict) -> Key:
    k = Key(
        key=base64.b64decode(d["key"]),
        sig=base64.b64decode(d["sig"]),
    )
    # Overwrite Key's auto-generated UUID with the original
    k.id = uuid.UUID(d["id"])
    return k

def keysbundle_to_dict(bundle: KeysBundle) -> dict:
    return {
        "lr": key_to_dict(bundle.lr),       # Bob’s last-resort key
        "ots": [key_to_dict(k) for k in bundle.ots],  # Bob’s one-time keys
    }

def dict_to_keysbundle(d: dict) -> KeysBundle:
    lr_key = dict_to_key(d["lr"])
    ots_keys = [dict_to_key(kd) for kd in d["ots"]]
    return KeysBundle(lr_key, ots_keys)

def initmsg_to_dict(msg: InitMessage) -> dict:
    return {
        "key_id": str(msg.key_id),
        "c": base64.b64encode(msg.c).decode("utf-8"),
        "enc_msg": base64.b64encode(msg.enc_msg).decode("utf-8"),
        "iv": base64.b64encode(msg.iv).decode("utf-8"),
        "msg_sig": base64.b64encode(msg.msg_sig).decode("utf-8"),
    }

def dict_to_initmsg(d: dict) -> InitMessage:
    return InitMessage(
        key_id=uuid.UUID(d["key_id"]),
        c=base64.b64decode(d["c"]),
        enc_msg=base64.b64decode(d["enc_msg"]),
        iv=base64.b64decode(d["iv"]),
        msg_sig=base64.b64decode(d["msg_sig"]),
    )
