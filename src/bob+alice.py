from dilithium_py.dilithium import Dilithium3
from receiver import Receiver
from sender import construct_init_msg
from aead import encrypt_msg
from Crypto.Random import get_random_bytes

bob_pk, bob_sk = Dilithium3.keygen()
alice_pk, alice_sk = Dilithium3.keygen()

rsv = Receiver(bob_sk)

bundle = rsv.get_key_bundle()

msg = b"Hello world some random long super long string"

init_msg = construct_init_msg(alice_sk, bob_pk, bundle, msg)

rsvd_msg = rsv.receive_init_msg(alice_pk, init_msg)

print(rsvd_msg)