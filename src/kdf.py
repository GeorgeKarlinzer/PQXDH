from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

curve = "CURVE25519"
hash_alg = "SHA-512"
pqkem = "CRYSTALS-KYBER-1024"

# Construct the HKDF info string
info_str = f"MyProtocol_{curve}_{hash_alg}_{pqkem}"
info = info_str.encode('utf-8')

# Define the salt as a zero-filled byte sequence equal to the hash output length
salt_length = 64
salt = bytes(salt_length)

# Set the curve-based prefix (32 bytes of 0xFF for CURVE25519, 57 bytes for CURVE448)
prefix_length = 32
prefix = bytes([0xFF] * prefix_length)

# Define the input key material (KM) by concatenating the prefix with the secret key material
secret_key_material = b"input key"  # Replace with actual secret key
km = prefix + secret_key_material

# Create the HKDF instance with the specified parameters
hkdf = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    info=info,
)

# Derive the key
key = hkdf.derive(km)
print(len(key))