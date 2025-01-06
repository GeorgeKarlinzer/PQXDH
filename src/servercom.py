from dilithium_py.dilithium import Dilithium3
from receiver import Receiver
from sender import construct_init_msg
from KeysBundle import Key, KeysBundle
from serialization import (
    keysbundle_to_dict,
    dict_to_keysbundle,
    initmsg_to_dict,
    dict_to_initmsg
)
import requests
import base64
import uuid
def main():
    # --------------------------
    # (A) Bob's Setup
    # --------------------------
    print("==> Bob: Generating Dilithium keypair and Kyber bundle...")
    bob_pk, bob_sk = Dilithium3.keygen()
    rsv = Receiver(bob_sk)  # Generates Bob's Kyber LR + OTK keys
    bob_bundle = rsv.get_key_bundle()  # => KeysBundle

    # Publish Bob's bundle (Kyber public keys) to server
    print("==> Bob: Publishing key bundle to server.")
    publish_url = "http://127.0.0.1:5000/publish_bundle"
    bob_bundle_dict = keysbundle_to_dict(bob_bundle)
    resp = requests.post(publish_url, json=bob_bundle_dict)
    print("Server response:", resp.json())
    
    # --------------------------
    # (B) Alice's Setup
    # --------------------------
    print("\n==> Alice: Generating Dilithium keypair...")
    alice_pk, alice_sk = Dilithium3.keygen()

    # --------------------------
    # (C) Alice Fetches Bob's Bundle from Server
    # --------------------------
    get_bundle_url = "http://127.0.0.1:5000/get_bundle"
    resp = requests.get(get_bundle_url)
    if resp.status_code != 200:
        print("Error: could not fetch Bob's bundle")
        return
    bob_bundle_data = resp.json()  # base64-encoded dict
    bob_bundle_obj = dict_to_keysbundle(bob_bundle_data)

    # Bob’s Dilithium PK must also be known to Alice. For demo, we just have it in bob_pk:
    # In a real scenario, this might come from a separate publication/PKI.
    print("==> Alice: Constructing init message for Bob.")
    msg = b"Some super secret message"
    init_msg_obj = construct_init_msg(alice_sk, bob_pk, bob_bundle_obj, msg)
    
    # Send init message to server
    print("==> Alice: Sending init message to server.")
    init_msg_dict = initmsg_to_dict(init_msg_obj)
    send_init_url = "http://127.0.0.1:5000/send_init_message"
    resp = requests.post(send_init_url, json=init_msg_dict)
    print("Server response:", resp.json())

    # --------------------------
    # (D) Bob Fetches and Decrypts the Init Message
    # --------------------------
    get_init_msg_url = "http://127.0.0.1:5000/get_init_message"
    resp = requests.get(get_init_msg_url)
    if resp.status_code != 200:
        print("Error: could not fetch init message")
        return
    
    init_msg_received_dict = resp.json()
    init_msg_received_obj = dict_to_initmsg(init_msg_received_dict)

    print("==> Bob: Decrypting/Verifying received message...")
    # Bob uses rsv to handle the message. He needs Alice's PK:
    # For the demo, we have `alice_pk` in this script:
    try:
        plaintext = rsv.receive_init_msg(alice_pk, init_msg_received_obj)
        print("Bob received message:", plaintext)
    except Exception as e:
        print("Error verifying/decrypting message:", str(e))

####################################
# Run the main function
####################################
if __name__ == "__main__":
    main()