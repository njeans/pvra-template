#!/bin/env python3

import json
import sys
import os
import crypto

from web3 import Web3
import solcx
from solcx import compile_source
import secp256k1

PROJECT_ROOT = os.environ.get('PROJECT_ROOT')
BILLBOARD_URL = os.environ.get('BILLBOARD_URL', 'http://localhost:8545')
NUM_USERS = os.environ.get('NUM_USERS', 2)
print("BILLBOARD_URL",BILLBOARD_URL)
CONTRACT_ADDRESS_PATH = os.environ.get('CONTRACT_ADDRESS_PATH', PROJECT_ROOT +"/billboard/contract_address")
ENCLAVE_PUBLIC_KEY_PATH = os.environ.get('ENCLAVE_PUBLIC_KEY_PATH', PROJECT_ROOT +"/test_sgx/signingkey.bin")
IAS_REPORT_PATH = os.environ.get('IAS_REPORT_PATH', PROJECT_ROOT +"/test_sgx/ias_report.json")
BILLBOARD_ACCOUNTS_PATH = os.environ.get('BILLBOARD_ACCOUNTS_PATH', PROJECT_ROOT+'/billboard/accounts.json')
SOLIDITY_PATHS = (PROJECT_ROOT+'/billboard/solidity/', 'Billboard.sol', [])

with open(ENCLAVE_PUBLIC_KEY_PATH, "rb") as f:
    enclave_public_key = f.read()
    if len(enclave_public_key) == 65:
        enclave_public_key = enclave_public_key[1:]

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
    secret_key = secp256k1.PrivateKey(private_key, raw=True)
    return Web3.toChecksumAddress(user_address), secret_key


def compile_source_file(base_path, contract_source_path, allowed):
    with open(base_path + contract_source_path, 'r') as f:
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
    with open(IAS_REPORT_PATH) as f:
        ias_report = json.loads(f.read())
    print("enclave_public_key=",enclave_public_key.hex())
    # print("ias_report_signature=", ias_report["headers"]["X-IASReport-Signature"])
    print("admin_addr=",admin_addr)
    tx_hash = contract.constructor(enclave_public_key, b'ias report').transact({"from": admin_addr})
    contract_address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
    contract = w3.eth.contract(address=contract_address, abi=abis)
    print(f'Deployed {contract_id} to: {contract_address} with hash  {tx_hash}')
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


def convert_publickey_address(publickey):
    h = Web3.sha3(hexstr=publickey)
    return Web3.toChecksumAddress(Web3.toHex(h[-20:]))


def send_tx(w3, foo, user_addr, value=0):
    # print("billboard.send_tx from address:", user_addr, foo)

    gas_estimate = foo.estimateGas()
    # print(f'\tGas estimate to transact: {gas_estimate}')

    if gas_estimate < 10000000:
        # print("\tSending transaction")
        tx_hash = foo.transact({"from": user_addr, "value": value})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # print("\tTransaction receipt mined:",receipt)
        return receipt.gasUsed
        # pprint.pprint(dict(receipt))
        # print("\tWas transaction successful?"+str(receipt["status"]))
    else:
        print("billboard.send_tx error Gas cost exceeds 1000000:", gas_estimate)
        exit(1)


def admin_init_contract(user_addresses_path, signature_path):
    print("admin_init_contract", "user_addresses_path", user_addresses_path, "signature_path", signature_path)
    w3 = setup_w3()
    _admin_addr, admin_pk = get_account(0)
    _,contract,_ = deploy_contract(w3, admin_addr=_admin_addr)
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open(user_addresses_path) as f:
        data = f.read().split("\n")[1:]
        user_addresses = [convert_publickey_address(x) for x in data]
    print("signature", len(signature), signature.hex())
    print("user_addresses", len(user_addresses), user_addresses)
    # address_data = bytes("".join(map(lambda x: x.lower(), user_addresses)), "utf-8")
    # print("".join(map(lambda x: x.lower(), user_addresses), bytes("".join(map(lambda x: x.lower(), user_addresses), "utf-8"))
    # crypto.verify_secp256k1_data(enclave_public_key, address_data, signature)
    ge = send_tx(w3, contract.functions.init_user_db(user_addresses, signature), _admin_addr)
    print("gasUsed", ge)

    tmp_addr = contract.functions.tmp_addr().call({"from": _admin_addr})
    tmp_hash = contract.functions.tmp_hash().call({"from": _admin_addr})
    tmp_b = contract.functions.tmp_byte().call({"from": _admin_addr})
    enclave_address = contract.functions.enclave_address().call({"from": _admin_addr})
    print("tmp_addr",tmp_addr, "enclave_address", enclave_address,"tmp_byte", tmp_b,"tmp_byte_hex", tmp_b.hex(), "tmp_hash", tmp_hash)

    initialized = contract.functions.initialized().call({"from": _admin_addr})
    assert initialized
    amount = contract.functions.max_penalty().call({"from": _admin_addr})
    send_tx(w3, contract.functions.fund(), _admin_addr, value=amount*10)


def user_add_data(user_num, encrypted_user_data_path):
    print("user_add_data", "user_num", user_num, "encrypted_user_data_path", encrypted_user_data_path)
    user_num = int(user_num)+1
    with open(encrypted_user_data_path, "rb") as f:
        encrypted_user_data = f.read()
    w3 = setup_w3()
    contract = get_contract(w3)
    user_addr, secret_key = get_account(user_num)
    last_audit_num = contract.functions.last_audit_num().call({"from": user_addr})
    audit_num = last_audit_num+1
    print("audit_num",audit_num)
    print("encrypted_user_data", len(encrypted_user_data), encrypted_user_data)
    ge = send_tx(w3, contract.functions.add_user_data(encrypted_user_data, audit_num), user_addr)
    print("gasUsed", ge)
    user_info = contract.functions.get_user(user_addr, audit_num).call({"from": user_addr})
    print("updated user", user_info)
    assert user_info[0] == user_addr
    assert user_info[1] == audit_num  # next_audit_num
    assert user_info[2] == encrypted_user_data  # user_data


if __name__ == '__main__':
    print(sys.argv[1:])
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 4:
        print(globals()[sys.argv[1]], sys.argv[2], sys.argv[3])
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
