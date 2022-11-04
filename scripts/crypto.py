
import secp256k1
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from web3.auto import w3
from eth_account.messages import encode_defunct

from utils import *

# data=bytes("abcdefghijklmnop\n","utf-8")
# date=bytes.fromhex("6162636465666768696a6b6c6d6e6f700a")
# n=bytes([0 for _ in range(12)])
# derived_key=bytes([0 for _ in range(16)])
# cipher = AES.new(derived_key, AES.MODE_GCM, nonce=n)
# ciphertext, tag = cipher.encrypt_and_digest(data)
# res=tag+cipher.nonce+ciphertext

def derive_key_aes(my_privatekey, other_publickey):
    if len(other_publickey) == 64:
        other_publickey = b'\x04' + other_publickey
    key = secp256k1.PublicKey(other_publickey, raw=True)
    shared_key = key.ecdh(my_privatekey, hashfn=secp256k1.lib.secp256k1_ecdh_hash_function_sha256)[:16]
    return shared_key


def encrypt_aes(derived_key, data):
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # print("tag",len(tag),"nonce",len(cipher.nonce), "ciphertext", len(ciphertext))
    return tag+cipher.nonce+ciphertext


def sign_secp256k1(raw_key, data):
    key = secp256k1.PrivateKey(raw_key, raw=True)
    sig = key.ecdsa_sign(data, digest=hashlib.sha3_256, raw=False)
    return key.ecdsa_serialize_compact(sig).hex()


def verify_secp256k1_path(publickey_path, data_path, signature_path):
    with open(publickey_path, "rb") as f:
        publickey = f.read()
    with open(data_path, "rb") as f:
        data = f.read()
    with open(signature_path, "rb") as f:
        sig_raw = f.read()
    if len(publickey) == 64:
        publickey = b'\x04' + publickey
    key = secp256k1.PublicKey(publickey, raw=True)
    sig = key.ecdsa_deserialize_compact(sig_raw)
    # print("key", publickey.hex())
    # print("data",len(data), data.hex())
    # print("sig_raw", sig_raw.hex())
    # res = key.ecdsa_verify(data, sig)
    # print(res)
    # assert res
    return key.ecdsa_verify(data, sig)


def verify_secp256k1_data(publickey, data, sig_raw):
    if len(publickey) == 64:
        publickey = b'\x04' + publickey
    key = secp256k1.PublicKey(publickey, raw=True)
    sig = key.ecdsa_deserialize_compact(sig_raw)
    # res = key.ecdsa_verify(data, sig)
    # assert res
    return key.ecdsa_verify(data, sig)


def sign_eth_data(private_key, data):
    data = encode_defunct(primitive=data)
    res = w3.eth.account.sign_message(data, private_key)
    return res.signature.hex()[2:]


def recover_eth_data(data, sig, publickey=None, address=None):
    if address is None:
        if len(publickey) == 65:
            publickey = publickey[1:]
        assert len(publickey) == 64
        address = convert_publickey_address(publickey.hex())
    enc_data = encode_defunct(primitive=data)
    res = w3.eth.account.recover_message(enc_data, signature=sig)
    eq = address.lower() == res.lower()
    # print(address.lower(), res.lower(), eq)
    return eq


def recover_eth_path(publickey_path, data_path, signature_path):
    with open(publickey_path, "rb") as f:
        publickey = f.read()
    with open(data_path, "rb") as f:
        data = f.read()
    with open(signature_path, "rb") as f:
        sig = f.read()
    if len(publickey) == 65:
        publickey = publickey[1:]
    data = encode_defunct(primitive=data)
    res = w3.eth.account.recover_message(data, signature=sig).lower()
    # eq = convert_publickey_address(publickey.hex()) == res
    # print(eq)
    # assert eq
    return convert_publickey_address(publickey.hex()) == res
