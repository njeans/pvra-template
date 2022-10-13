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
    print("enclave_public_key="+enclave_public_key.hex())
    # print("ias_report_signature=", ias_report["headers"]["X-IASReport-Signature"])
    print("admin_addr="+admin_addr)
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


def get_packed_address(address):
    if address[:2] == "0x":
        address = address[2:]
    return bytes.fromhex(address).rjust(32, b'\0')


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
        print("billboard.send_tx error Gas cost exceeds 10000000:", gas_estimate)
        exit(1)


def admin_init_contract(user_addresses_path, signature_path):
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open(user_addresses_path) as f:
        data = f.read().split("\n")[1:]
    user_addresses = [convert_publickey_address(x) for x in data]
    address_data = b"".join(map(get_packed_address, user_addresses))
    res = crypto.recover_eth_data(enclave_public_key, address_data, signature)
    print(res)
    assert res
    w3 = setup_w3()
    admin_addr_, admin_pk = get_account(0)
    _,contract,_ = deploy_contract(w3, admin_addr=admin_addr_)
    ge = send_tx(w3, contract.functions.init_user_db(user_addresses, signature), admin_addr_)
    print("gasUsed", ge)
    initialized = contract.functions.initialized().call({"from": admin_addr_})
    assert initialized


def user_add_data(user_num, encrypted_user_data_path):
    user_num = int(user_num)+1
    with open(encrypted_user_data_path, "rb") as f:
        encrypted_user_data = f.read()
    w3 = setup_w3()
    contract = get_contract(w3)
    user_addr, secret_key = get_account(user_num)
    last_audit_num = contract.functions.last_audit_num().call({"from": user_addr})
    audit_num = last_audit_num+1
    ge = send_tx(w3, contract.functions.add_user_data(encrypted_user_data, audit_num), user_addr)
    print("gasUsed", ge)
    user_info = contract.functions.get_user(user_addr, audit_num).call({"from": user_addr})
    assert user_info[0] == user_addr
    assert user_info[1] == audit_num  # next_audit_num
    assert user_info[2] == encrypted_user_data  # user_data


def admin_post_audit_data(data_path, signature_path, audit_num=1):
    with open(data_path, "rb") as f:
        audit_data_raw = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
    res = crypto.recover_eth_data(enclave_public_key, audit_data_raw, signature)
    print(res)
    assert res
    len_addr=32
    len_hash=32
    n=len_addr+len_hash
    audit_data = audit_data_raw
    start_data = len(str(audit_num))
    audit_data = [audit_data[i:i+len_addr] for i in range(start_data, len(audit_data_raw), 32)]
    audit_data = [audit_data[:int(len(audit_data)/2)], audit_data[int(len(audit_data)/2):]]
    audit_data = [[Web3.toChecksumAddress(x[-20:].hex()) for x in audit_data[0]], audit_data[1]]
    print("audit_data=", audit_data)
    w3 = setup_w3()
    contract = get_contract(w3)
    admin_addr, _ = get_account(0)
    audit_num = int(audit_num)
    gas=send_tx(w3, contract.functions.admin_audit(audit_num, signature, audit_data[0], audit_data[1]), user_addr=admin_addr)
    last_audit_num = contract.functions.last_audit_num().call({"from": admin_addr})
    assert last_audit_num == audit_num
    print("gasUsed",gas)


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
