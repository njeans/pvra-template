#!/bin/env python3

import json
import sys
import os
import time
import web3
from web3 import Web3
import solcx
from solcx import compile_source
import secp256k1

from utils import *
from constants import *

FILENAME="billboard.py"

def setup_w3(bb_url=BILLBOARD_URL):
    connected = False
    max_tries = 10
    num_tries = 0
    while not connected:
        try:
            provider = Web3.HTTPProvider(bb_url, request_kwargs={'timeout': 60})
            w3 = Web3(provider)
            latest_block = w3.eth.get_block('latest')
            connected = True
        except Exception as e:
            if num_tries >= max_tries:
                raise e
            print("waiting to connect to bulletin board...")
            time.sleep(5)
            num_tries+=1
            pass

    return w3


def get_account(user_num, accounts_path=BILLBOARD_ACCOUNTS_PATH):
    user_num = int(user_num)
    with open(accounts_path) as f:
        accounts = json.load(f)
    user_address = accounts["available_accounts"][user_num]
    priv = bytes.fromhex(accounts["private_keys"][user_num][2:])
    pub = secp256k1.PrivateKey(priv, raw=True).pubkey.serialize(compressed=False)[1:]
    return (Web3.toChecksumAddress(user_address), pub, priv)


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


def deploy_contract(w3=setup_w3(), admin_addr=""):
    if admin_addr == "":
        admin_addr, _, _ = get_account(0)
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
    contract_address = None
    while contract_address is None:
        try:
           contract_address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
        except web3.exceptions.TransactionNotFound:
            time.sleep(1)
    contract = w3.eth.contract(address=contract_address, abi=abis)
    print_(f'Deployed {contract_id} to: {contract_address} with hash  {tx_hash.hex()}', n=FILENAME)
    with open(CONTRACT_ADDRESS_PATH, "w") as f:
        f.write(contract_address)
    return contract_address, contract, contract_id


def get_contract(w3, contract_address_path=CONTRACT_ADDRESS_PATH, solidity_paths=SOLIDITY_PATHS):
    base_path, contract_source_path, allowed = solidity_paths
    contract_id,abis,bins = compile_source_file(base_path, contract_source_path, allowed)
    with open(contract_address_path) as f:
        contract_address = f.read()
    contract = w3.eth.contract(abi=abis, bytecode=bins, address=contract_address)
    return contract


def gen_keys(num_users=NUM_USERS):
    print_vv("num_users", num_users, n=FILENAME)
    with open(BILLBOARD_ACCOUNTS_PATH) as f:
        accounts = json.load(f)
    user_addresses = accounts["available_accounts"]
    public_keys = ["" for _ in range(num_users+1)]
    keys = ["" for _ in range(num_users+1)]
    for i in range(num_users+1):
        address = user_addresses[i]  # admin is account at position 0
        priv = bytes.fromhex(accounts["private_keys"][i][2:])
        pub = secp256k1.PrivateKey(priv, raw=True).pubkey.serialize(compressed=False)[1:]
        public_keys[i] = pub.hex()
        keys[i] = (Web3.toChecksumAddress(address), pub, priv)
        print_vv(f" user {i}: address: {print_hex_trunc(address)} pubkey: {print_hex_trunc(pub)}", n=FILENAME)
    with open(USER_LIST_PATH, "w") as f:
        # f.write(str(num_users+1) + "\n")
        f.write("\n".join(public_keys))
    return keys


def send_tx(w3, foo, user_addr, value=0):
    print_vv(f"send_tx from address: {user_addr} {foo}", n=FILENAME)
    try:
        gas_estimate = foo.estimateGas()  # for some reason this fails sometimes when it shouldn't
    except Exception as e:
        print_(f"estimate gas error {e}", c=ERRORc, n=FILENAME)
        gas_estimate = 0

    if gas_estimate < 10000000:
        tx_hash = foo.transact({"from": user_addr, "value": value})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print_vv(f"transaction receipt mined: {receipt}", n=FILENAME)
        return receipt.gasUsed
    else:
        print_(f"send_tx error Gas cost exceeds 10000000 < {gas_estimate}", c=ERRORc, n=FILENAME)
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