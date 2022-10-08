import secp256k1
import hashlib
import sys

with open("enclave_enc_pubkey.bin", "rb") as f:
    other_publickey = f.read()
with open(sys.argv[1], "rb") as f:
    my_privatekey = f.read()

#print("my_privatekey", my_privatekey)

if len(other_publickey) == 64:
    other_publickey = b'\x04' + other_publickey
key = secp256k1.PublicKey(other_publickey, raw=True)
shared_key = key.ecdh(my_privatekey)#, hashfn=hashlib.sha256)#secp256k1.lib.secp256k1_ecdh_hash_function_sha256)

#print(shared_key.hex())

with open("sessionAESkey.bin", "wb") as f:
    f.write(shared_key)
