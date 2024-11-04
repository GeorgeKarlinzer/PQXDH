import os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kyber import Kyber512

# Helper function to generate random bytes
def generate_random_bytes(length):
    return os.urandom(length)

# Helper function to encode an elliptic curve public key
def encode_ec(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

# Helper function to encode a pqkem public key
def encode_kem(pqkem_public_key):
    return pqkem_public_key

# Helper function to sign data using Ed25519
def sign_data(private_key, data):
    return private_key.sign(data)

# Helper function to verify signatures using Ed25519
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

# Helper function to derive a shared key using HKDF
def derive_key(material):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=b"PQXDH_key_derivation"
    )
    return hkdf.derive(material)

# Step 3.2: Bob publishes his keys
def publish_bob_keys():
    # Generate Bob's identity key (Ed25519) for signing
    bob_identity_private_key = ed25519.Ed25519PrivateKey.generate()
    bob_identity_public_key = bob_identity_private_key.public_key()

    # Generate Bob's X25519 identity key for key exchange
    bob_x25519_private_key = x25519.X25519PrivateKey.generate()
    bob_x25519_public_key = bob_x25519_private_key.public_key()

    # Generate Bob's signed curve prekey (X25519 for key exchange)
    signed_curve_prekey_private = x25519.X25519PrivateKey.generate()
    signed_curve_prekey_public = signed_curve_prekey_private.public_key()
    signature_spk = sign_data(bob_identity_private_key, encode_ec(signed_curve_prekey_public))

    # Generate Bob's last-resort pqkem prekey (CRYSTALS-Kyber)
    pqkem_public_key, pqkem_private_key = Kyber512.keygen()
    signature_pqspk = sign_data(bob_identity_private_key, encode_kem(pqkem_public_key))

    # Construct Bob's prekey bundle
    bob_prekey_bundle = {
        "IKB": bob_x25519_public_key,  # Use X25519 public key for key exchange
        "SPKB": (signed_curve_prekey_public, "IdEC_SPKB", signature_spk),
        "PQPKB": (pqkem_public_key, "IdKEM_PQPKB", signature_pqspk),
        "SignKey": bob_identity_public_key  # Include the Ed25519 public key for signature verification
    }
    
    # Bob's private keys needed for decryption later
    bob_private_keys = {
        "x25519_private_key": bob_x25519_private_key,
        "signed_curve_prekey_private": signed_curve_prekey_private,
        "pqkem_private_key": pqkem_private_key
    }

    return bob_prekey_bundle, bob_private_keys

# Step 3.3: Alice sends the initial message
def send_initial_message(bob_prekey_bundle):
    # Generate Alice's X25519 identity key for key exchange
    IKA_private = x25519.X25519PrivateKey.generate()
    IKA = IKA_private.public_key()

    # Fetch Bob's keys and signatures from the bundle
    IKB = bob_prekey_bundle["IKB"]
    SPKB, IdEC_SPKB, Sig_SPKB = bob_prekey_bundle["SPKB"]
    PQPKB, IdKEM_PQPKB, Sig_PQPKB = bob_prekey_bundle["PQPKB"]
    sign_key = bob_prekey_bundle["SignKey"]

    # Verify Bob's signatures using the Ed25519 public key
    if not (verify_signature(sign_key, encode_ec(SPKB), Sig_SPKB) and 
            verify_signature(sign_key, encode_kem(PQPKB), Sig_PQPKB)):
        raise ValueError("Signature verification failed. Aborting protocol.")

    # Generate Alice's ephemeral key pair
    EKA_private = x25519.X25519PrivateKey.generate()
    EKA = EKA_private.public_key()

    # Encapsulate shared secret using CRYSTALS-Kyber
    CT, SS = Kyber512.enc(PQPKB)

    # Calculate DH values correctly
    DH1 = IKA_private.exchange(SPKB)  # Alice uses her identity private key and Bob's signed prekey public key
    DH2 = EKA_private.exchange(IKB)   # Alice uses her ephemeral private key and Bob's identity public key
    DH3 = EKA_private.exchange(SPKB)
    SK_material = DH1 + DH2 + DH3 + SS
    print("Alice's DH1:", DH1.hex())
    print("Alice's DH2:", DH2.hex())
    print("Alice's DH3:", DH3.hex())
    print("Alice's SS:", SS.hex())
    # Derive session key (SK)
    SK = derive_key(SK_material)
    print("Send:", SK.hex())

    # Compute associated data (AD)
    AD = encode_ec(IKA) + encode_ec(IKB) + encode_kem(PQPKB)

    # Encrypt initial message using SK and AD
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(SK), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(AD)
    initial_ciphertext = encryptor.update(b"Initial message") + encryptor.finalize()
    tag = encryptor.tag  # Capture the authentication tag

    # Construct the initial message
    initial_message = {
        "IKA": encode_ec(IKA),
        "EKA": encode_ec(EKA),
        "CT": CT,
        "PrekeyIdentifiers": {
            "SPKB": IdEC_SPKB,
            "PQPKB": IdKEM_PQPKB
        },
        "Ciphertext": initial_ciphertext,
        "Nonce": nonce,
        "Tag": tag  # Include the authentication tag
    }
    return initial_message

# Step 3.4: Bob receives the initial message
def receive_initial_message(initial_message, bob_prekey_bundle, bob_private_keys):
    # Unpack Bob's private keys
    bob_x25519_private_key = bob_private_keys["x25519_private_key"]
    signed_curve_prekey_private = bob_private_keys["signed_curve_prekey_private"]
    pqkem_private_key = bob_private_keys["pqkem_private_key"]

    # Unpack the initial message from Alice
    IKA = x25519.X25519PublicKey.from_public_bytes(initial_message["IKA"])
    EKA = x25519.X25519PublicKey.from_public_bytes(initial_message["EKA"])
    CT = initial_message["CT"]
    IdEC_SPKB = initial_message["PrekeyIdentifiers"]["SPKB"]
    IdKEM_PQPKB = initial_message["PrekeyIdentifiers"]["PQPKB"]
    ciphertext = initial_message["Ciphertext"]
    nonce = initial_message["Nonce"]
    tag = initial_message["Tag"]  # Retrieve the authentication tag

    # Retrieve PQPKB from Bob's prekey bundle
    PQPKB = bob_prekey_bundle["PQPKB"][0]  # Access the public key from the prekey bundle

    # Calculate DH values correctly
    DH1 = signed_curve_prekey_private.exchange(IKA)
    DH2 = bob_x25519_private_key.exchange(EKA)
    DH3 = signed_curve_prekey_private.exchange(EKA)
    # Decapsulate the shared secret using CRYSTALS-Kyber
    SS = Kyber512.dec(CT, pqkem_private_key)

    # Derive session key (SK)
    SK_material = DH1 + DH2 + DH3 + SS
    SK = derive_key(SK_material)
    print("Rcv:", SK.hex())
    print("Bob's DH1:", DH1.hex())
    print("Bob's DH2:", DH2.hex())
    print("Bob's DH3:", DH3.hex())
    print("Bob's SS:", SS.hex())

    # Corrected computation of associated data (AD)
    AD = encode_ec(IKA) + encode_ec(bob_x25519_private_key.public_key()) + encode_kem(PQPKB)

    # Decrypt the initial message using SK, AD, and the authentication tag
    cipher = Cipher(algorithms.AES(SK), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(AD)
    
    try:
        # Decrypt the ciphertext
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        print("Decrypted message:", decrypted_message.decode())
        
        # Successful decryption
        return {
            "status": "success",
            "decrypted_message": decrypted_message
        }
    except Exception as e:
        # If decryption fails, return an error
        print("Decryption failed:", str(e))
        return {
            "status": "failure",
            "error": str(e)
        }

# Example usage
bob_prekey_bundle, bob_private_keys = publish_bob_keys()  # Bob publishes his keys
message = send_initial_message(bob_prekey_bundle)  # Alice sends the initial message
result = receive_initial_message(message, bob_prekey_bundle, bob_private_keys)  # Bob receives the initial message
print("Result:", result)