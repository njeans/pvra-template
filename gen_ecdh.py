import secp256k1
import hashlib
import sys

def swap_endians(b, *, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, "big")

with open("enclave_enc_pubkey.bin", "rb") as f:
    other_publickey = f.read()
x_little = other_publickey[:32]
y_little = other_publickey[32:]
x = swap_endians(x_little)
y = swap_endians(y_little)
other_publickey = b"\x04" + x + y
print("enclave_enc_pubkey.bin", other_publickey.hex())

with open(sys.argv[1], "rb") as f:
    my_privatekey = f.read()

key = secp256k1.PublicKey(other_publickey, raw=True)
shared_key = key.ecdh(my_privatekey)

with open("sessionAESkey.bin", "wb") as f:
    f.write(shared_key)
