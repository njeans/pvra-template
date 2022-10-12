import sys
import secp256k1
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
from web3 import Web3


def derive_key_aes(my_privatekey, other_publickey):
    if len(other_publickey) == 64:
        other_publickey = b'\x04' + other_publickey
    key = secp256k1.PublicKey(other_publickey, raw=True)
    shared_key = key.ecdh(my_privatekey, hashfn=secp256k1.lib.secp256k1_ecdh_hash_function_sha256)
    return shared_key


def encrypt_aes(derived_key, data):
    cipher = AES.new(derived_key,AES.MODE_GCM,nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # print("tag",len(tag),tag)
    # print("cipher.nonce",len(cipher.nonce),cipher.nonce)
    # print("ciphertext",len(ciphertext),ciphertext)

    #return: encrypted_message[*]tag[16]iv[12]
    return ciphertext+tag+cipher.nonce


def sign_secp256k1(raw_key, data):
    key = secp256k1.PrivateKey(raw_key, raw=True)
    # print(data)
    sig = key.ecdsa_sign(data, digest=hashlib.sha3_256, raw=False)
    print("~~key.ecdsa_serialize_compact(sig)",len(key.ecdsa_serialize_compact(sig)),key.ecdsa_serialize_compact(sig))
    return key.ecdsa_serialize_compact(sig).hex()


def verify_secp256k1(publickey_path, data_path, signature_path, eth=True):
    with open(publickey_path, "rb") as f:
        publickey = f.read()
    with open(data_path, "rb") as f:
        data = f.read()
    with open(signature_path, "rb") as f:
        sig_raw = f.read()
    if len(publickey) == 64:
        publickey = b'\x04' + publickey
    key = secp256k1.PublicKey(publickey, raw=True)
    sig = key.ecdsa_deserialize_compact(sig_raw[:64])
    if eth:
        data = b'\x19Ethereum Signed Message:\n' + bytes(len(data)) + data
    res = key.ecdsa_verify(data, sig, digest=hashlib.sha3_256)
    print("data", data.hex())
    print("sig", sig_raw.hex())
    print("public key", publickey.hex())
    print(res)
    # assert res
    return res

def verify_secp256k1_data(publickey, data, sig_raw, eth=True):
    if len(publickey) == 64:
        publickey = b'\x04' + publickey
    key = secp256k1.PublicKey(publickey, raw=True)
    sig = key.ecdsa_deserialize_compact(sig_raw[:64])
    if eth:
        data = b'\x19Ethereum Signed Message:\n' + bytes(len(data)) + data
    res = key.ecdsa_verify(data, sig, digest=hashlib.sha3_256)
    print("data", data.hex())
    print("sig", sig_raw.hex())
    print("public key", publickey.hex())
    print(res)
    assert res
    return res

def verify_ias_report(report, report_key, report_sig):
    pass


def convert_publickey_address(publickey):
    h = Web3.sha3(hexstr=publickey)
    return Web3.toHex(h[-20:])

if __name__ == '__main__':
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 4:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
