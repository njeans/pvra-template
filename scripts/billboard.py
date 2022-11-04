#!/bin/env python3

import json
import sys
import os
import hashlib

from web3 import Web3
import solcx
from solcx import compile_source
import secp256k1

from utils import *
from constants import *


def print_vv(*args, c=""):
    if verbose >= 2:
        print(c+"[billboard.py]", *args)
        print(NOCOLOR, end="")


def print_(*args, c=""):
    print(c+"[billboard.py]", *args)
    print(NOCOLOR, end="")


def setup_w3(bb_url=BILLBOARD_URL):
    provider = Web3.HTTPProvider(bb_url, request_kwargs={'timeout': 60})
    w3 = Web3(provider)
    return w3


def get_account(user_num, accounts_path=BILLBOARD_ACCOUNTS_PATH):
    user_num = int(user_num)
    with open(accounts_path) as f:
        accounts_info = json.loads(f.read())
    user_address = list(accounts_info["addresses"].keys())[user_num]
    private_key = bytes(accounts_info["addresses"][user_address]["secretKey"]["data"])
    # secret_key = secp256k1.PrivateKey(private_key, raw=True)
    return Web3.toChecksumAddress(user_address), private_key


def compile_source_file(base_path, contract_source_path, allowed):
    with open(os.path.join(base_path, contract_source_path), 'r') as f:
        contract_source_path = f.read()
    compiled_sol = compile_source(contract_source_path,
                                  output_values=['abi', 'bin'],
                                  base_path=base_path,
                                  allow_paths=[allowed])
    abis = []
    bins = ""
    contract_id = ""
    for x in compiled_sol:
        contract_id += x
        contract_interface=compiled_sol[x]
        abis = abis + contract_interface['abi']
        bins = bins + contract_interface['bin']
    return contract_id, abis, bins


def deploy_contract(w3, admin_addr=""):
    if admin_addr == "":
        admin_addr,_ = get_account(0)
    base_path, contract_source_path, allowed = SOLIDITY_PATHS
    contract_id,abis,bins = compile_source_file(base_path, contract_source_path, allowed)
    contract = w3.eth.contract(abi=abis, bytecode=bins)
    # with open(IAS_REPORT_PATH) as f:
    #     ias_report = bytes(json.loads(f.read()), "utf-8")
    # print("enclave_public_key="+ENCLAVE_PUBLIC_KEY().hex())
    # print("enclave_addr="+convert_publickey_address(ENCLAVE_PUBLIC_KEY().hex()))
    # print("ias_report_signature=", ias_report["headers"]["X-IASReport-Signature"])
    # print("admin_addr="+admin_addr)
    tx_hash = contract.constructor(ENCLAVE_PUBLIC_KEY(), b'{"ias":"report"}').transact({"from": admin_addr})
    contract_address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
    contract = w3.eth.contract(address=contract_address, abi=abis)
    print_(f'Deployed {contract_id} to: {contract_address} with hash  {tx_hash.hex()}')
    with open(CONTRACT_ADDRESS_PATH, "w") as f:
        f.write(contract_address)
    return contract_address, contract, tx_hash


def get_contract(w3, contract_address_path=CONTRACT_ADDRESS_PATH, solidity_paths=SOLIDITY_PATHS):
    base_path, contract_source_path, allowed = solidity_paths
    contract_id,abis,bins = compile_source_file(base_path, contract_source_path, allowed)
    with open(contract_address_path) as f:
        contract_address = f.read()
    contract = w3.eth.contract(abi=abis, bytecode=bins, address=contract_address)
    return contract


def get_keys(num_users=NUM_USERS):
    print_vv("num_users", num_users)
    with open(BILLBOARD_ACCOUNTS_PATH) as f:
        accounts = json.loads(f.read())
    user_addresses = list(accounts["addresses"].keys())
    public_key = ["" for _ in range(num_users+1)]
    keys = ["" for _ in range(num_users+1)]
    for i in range(num_users+1):
        address = user_addresses[i]  # admin is account at position 0
        priv = bytes(accounts["addresses"][address]["secretKey"]["data"])
        pub = bytes(accounts["addresses"][address]["publicKey"]["data"])
        public_key[i] = pub.hex()
        keys[i] = (Web3.toChecksumAddress(address), pub, priv)
        print_vv(f" user {i}: address: {print_hex_trunc(address)} pubkey: {print_hex_trunc(pub)}")
    with open(USER_LIST_PATH, "w") as f:
        f.write(str(num_users+1) + "\n")
        f.write("\n".join(public_key))
    return keys


def send_tx(w3, foo, user_addr, value=0):
    print_vv(f"send_tx from address: {user_addr} {foo}")
    gas_estimate = foo.estimateGas()

    if gas_estimate < 10000000:
        tx_hash = foo.transact({"from": user_addr, "value": value})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print_vv(f"transaction receipt mined: {receipt}")
        return receipt.gasUsed
    else:
        print_(f"send_tx error Gas cost exceeds 10000000 < {gas_estimate}", c=ERRORc)
        exit(1)


if __name__ == '__main__':
    # print(sys.argv[1:])
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 4:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 6:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])