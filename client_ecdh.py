import base64
import json
import os
import pathlib
import sys
import time

import requests

from blessings import Terminal
from colorama import init as init_colorama  # , Fore, Back, Style
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def little2big_endian(b):
    return swap_endians(b)


def swap_endians(b, *, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, "big")

init_colorama()
term = Terminal()


CLIENT_DIR = pathlib.Path("./")
with open(CLIENT_DIR.joinpath("user0_pubkey.bin"), "rb") as f:
    pubkey_bytes = f.read()
    #print(pubkey_bytes)

with open(CLIENT_DIR.joinpath("user0_prikey.bin"), "rb") as f:
    prikey_bytes = f.read()
    #print(prikey_bytes)


x_little = pubkey_bytes[:32]
y_little = pubkey_bytes[32:]
x = little2big_endian(x_little)
y = little2big_endian(y_little)
point = b"\x04" + x + y
pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP256K1(), data=point)

pubkey_pem = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(f"{term.blue}{pubkey_pem.decode()}{term.normal}")

original_stdout = sys.stdout
with open('./user0_pubkey.pem', 'w') as f:
    sys.stdout = f # Change the standard output to the file we created.
    print(f"{pubkey_pem.decode()}")
    sys.stdout = original_stdout
