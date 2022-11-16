import sys
import hashlib
import json
import os

from web3 import Web3

from constants import *


def swap_endians(b, *, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, to_byteorder)


def verify_ias_report(report, report_key, report_sig):
    pass


def convert_publickey_address(publickey):
    if type(publickey) == str:
        if publickey[:2] == "0x":
            publickey = publickey[2:]
        publickey = bytes.fromhex(publickey)
    if len(publickey) == 65:
        publickey = publickey[1:]
    h = Web3.sha3(primitive=publickey)
    return Web3.toChecksumAddress(Web3.toHex(h[-20:]))


def get_packed_address(address):
    if address[:2] == "0x":
        address = address[2:]
    return bytes.fromhex(address).rjust(32, b'\0')


def get_address_from_packed(address):
    return Web3.toChecksumAddress(address[-20:].hex())


def print_hex_trunc(val):
    if type(val) == bytes:
        val = val.hex()
    if val[:2] == "0x":
        val = val[2:]
    l = min(3, int(len(val)/2))
    return "0x" + val[:l]+"..."+val[-l:]


def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def sha3(data):
    # m = hashlib.sha3_256()
    # m.update(data)
    # return m.digest()
    return Web3.sha3(primitive=data)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 4:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
