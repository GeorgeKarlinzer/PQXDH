from dilithium_py.dilithium import Dilithium3
from Receiver import Receiver
from Sender import construct_init_msg

bob_pk, bob_sk = Dilithium3.keygen()
alice_pk, alice_sk = Dilithium3.keygen()

rsv = Receiver(bob_sk)

bundle = rsv.get_key_bundle()

msg = b"Some super secret message"

init_msg = construct_init_msg(alice_sk, bob_pk, bundle, msg)

rsvd_msg = rsv.receive_init_msg(alice_pk, init_msg)

print(rsvd_msg)