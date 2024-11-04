from kyber import Kyber512
pk, sk = Kyber512.keygen()
c, key = Kyber512.enc(pk)
_key = Kyber512.dec(c, sk)
print("challenge", c)
print("\n\n\nshared key", key)
print("\n\n\ngecr shared key", _key)
assert key == _key