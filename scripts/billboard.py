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
    print(f'[billboard] Deployed {contract_id} to: {contract_address} with hash  {tx_hash.hex()}')
    with open(CONTRACT_ADDRESS_PATH, "w") as f:
        f.write(contract_address)
    return contract_address, contract, tx_hash


def get_contract(w3, contract_address_path=CONTRACT_ADDRESS_PATH, solidity_paths=SOLIDITY_PATHS):
    base_path, contract_source_path, allowed = solidity_paths
    contract_id,abis,bins = compile_source_file(base_path, contract_source_path, allowed)
    with open(contract_address_path) as f:
        contract_address = f.read()
    # print("contract_address", contract_address)
    contract = w3.eth.contract(abi=abis, bytecode=bins, address=contract_address)
    return contract


def get_keys(num_users=NUM_USERS):
    print("num_users", num_users)
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
        print("[billboard] send_tx error Gas cost exceeds 10000000:", gas_estimate)
        exit(1)


def admin_init_contract(user_addresses_path, signature_path):
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open(user_addresses_path) as f:
        data = f.read().split("\n")[1:]
    user_addresses = [convert_publickey_address(x) for x in data]
    address_data = b"".join(map(get_packed_address, user_addresses))
    res = crypto.recover_eth_data(address_data, signature, publickey=enclave_public_key)
    print(res)
    assert res
    w3 = setup_w3()
    admin_addr_, _ = get_account(0)
    _,contract,_ = deploy_contract(w3, admin_addr=admin_addr_)
    print("[billboard] initializing contract with users ", user_addresses)
    ge = send_tx(w3, contract.functions.init_user_db(user_addresses, signature), admin_addr_)
    print("[billboard] gasUsed", ge)
    initialized = contract.functions.initialized().call({"from": admin_addr_})
    assert initialized


#todo add user_verify_contract

def user_add_data(user_num, encrypted_user_data_path):
    user_num = int(user_num)+1
    with open(encrypted_user_data_path, "rb") as f:
        encrypted_user_data = f.read()
    w3 = setup_w3()
    contract = get_contract(w3)
    user_addr, _ = get_account(user_num)
    last_audit_num = contract.functions.last_audit_num().call({"from": user_addr})
    audit_num = last_audit_num+1

    ge = send_tx(w3, contract.functions.add_user_data(encrypted_user_data, audit_num), user_addr)
    print("[billboard] gasUsed", ge)

    user_info = contract.functions.get_user(user_addr, audit_num).call({"from": user_addr})
    print("[billboard] updated billboard user state for audit_num", audit_num, user_info)
    assert user_info[0] == user_addr
    assert user_info[1] == audit_num  # next_audit_num
    assert user_info[2] == encrypted_user_data  # user_data


def admin_post_audit_data(data_path, signature_path, audit_num=1):
    with open(data_path, "rb") as f:
        audit_data_raw = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
    res = crypto.recover_eth_data(audit_data_raw, signature, publickey=ENCLAVE_PUBLIC_KEY())
    print(res)
    assert res
    len_unit = 32
    audit_data = audit_data_raw
    print("[billboard] audit_data_raw",audit_data_raw.hex())
    start_data = len(str(audit_num))
    audit_data = [audit_data[i:i+len_unit] for i in range(start_data, len(audit_data_raw), 32)]
    audit_data = [audit_data[:int(len(audit_data)/2)], audit_data[int(len(audit_data)/2):]]
    audit_data = [[Web3.toChecksumAddress(x[-20:].hex()) for x in audit_data[0]], audit_data[1]]
    w3 = setup_w3()
    contract = get_contract(w3)
    admin_addr, _ = get_account(0)
    audit_num = int(audit_num)
    print("[billboard] posting audit_data for audit_num", audit_num, audit_data)
    # last_audit_num = contract.functions.last_audit_num().call({"from": admin_addr})
    # print("last_audit_num", last_audit_num)
    gas=send_tx(w3, contract.functions.admin_audit(audit_num, signature, audit_data[0], audit_data[1]), user_addr=admin_addr)
    print("[billboard] gasUsed", gas)
    # tmp_byte = contract.functions.tmp_byte().call({"from": admin_addr})
    # tmp_hash = contract.functions.tmp_hash().call({"from": admin_addr})
    # tmp_addr = contract.functions.tmp_addr().call({"from": admin_addr})
    # ee = contract.functions.enclave_address().call({"from": admin_addr})
    # print("tmp_byte", tmp_byte.hex())
    # print("tmp_hash", tmp_hash.hex())
    # print("tmp_addr", tmp_addr)
    # print("enclave_address", ee)
    last_audit_num = contract.functions.last_audit_num().call({"from": admin_addr})
    assert last_audit_num == audit_num


def admin_get_bb_data(output_base_path, audit_num=1):
    w3 = setup_w3()
    contract = get_contract(w3)
    admin_addr, _ = get_account(0)
    audit_num = int(audit_num)

    user_datas = contract.functions.get_all_user_data(audit_num).call({"from": admin_addr})
    print("[billboard] user data for audit_num", audit_num, user_datas)
    encrypted_data = []
    for user in user_datas:
        encrypted_data.append(user[2])
    for i in range(len(encrypted_data)):
        with open(output_base_path + "/command"+str(i)+".bin", "wb") as f:
            f.write(encrypted_data[i])


def admin_sign_confirmation(user_cmd_path, sig_out_path, msg_out_path):
    with open(user_cmd_path, "rb") as f:
        user_cmd_buff = f.read()
    user_pubkey = user_cmd_buff[:64]
    user_cmd = user_cmd_buff[64:]
    w3 = setup_w3()
    contract = get_contract(w3)
    admin_addr, private_key = get_account(0)
    last_audit_num = contract.functions.last_audit_num().call({"from": admin_addr})
    audit_num = last_audit_num+1
    user_addr = bytes.fromhex(crypto.convert_publickey_address(user_pubkey.hex())[2:])
    m = hashlib.sha3_256()
    m.update(user_cmd)
    user_cmd_hash = m.digest()
    confirmation = bytes(str(audit_num), "utf-8") + user_addr + user_cmd_hash
    sig = crypto.sign_eth_data(private_key, confirmation)
    with open(sig_out_path, "w") as f:
        f.write(sig[2:])
    with open(msg_out_path, "w") as f:
        f.write(confirmation.hex())


def user_verify_confirmation(user_num, cResponse_path, data_path):
    with open(cResponse_path, "r") as f:
        cResponse = json.loads(f.read())
    with open(data_path, "rb") as f:
        data = f.read()
    user_num = int(user_num)+1
    m = hashlib.sha3_256()
    m.update(data)
    data_hash = m.digest()
    user_addr, _ = get_account(user_num)
    w3 = setup_w3()
    contract = get_contract(w3)
    admin_addr = contract.functions.admin_addr().call({"from": user_addr})
    msg = bytes.fromhex(cResponse["msg_admin"])
    res = crypto.recover_eth_data(msg, bytes.fromhex(cResponse["sig_admin"]), address=admin_addr)
    print(res)
    assert res
    len_audit_num = len(msg) - 20 - 32
    listed_audit_num = int(msg[:len_audit_num])
    listed_address = msg[len_audit_num:len_audit_num+20]
    listed_data_hash = msg[len_audit_num+20:]
    assert listed_address.hex() == user_addr.lower()[2:]
    assert listed_data_hash == data_hash
    last_audit_num = contract.functions.last_audit_num().call({"from": admin_addr})
    assert listed_audit_num == last_audit_num+1


def user_verify_omission_sig(user_num, cResponse_path):
    with open(cResponse_path, "r") as f:
        cResponse = json.loads(f.read())
    msg = bytes.fromhex(cResponse["msg_admin"])
    sig = bytes.fromhex(cResponse["sig_admin"])
    user_num = int(user_num)+1
    user_addr, _ = get_account(user_num)
    w3 = setup_w3()
    contract = get_contract(w3)
    len_audit_num = len(msg) - 20 - 32
    audit_num = int(msg[:len_audit_num])
    listed_address = msg[len_audit_num:len_audit_num+20]
    listed_data_hash = msg[len_audit_num+20:]
    ge = send_tx(w3, contract.functions.prove_omission_sig(listed_address, audit_num, listed_data_hash, sig), user_addr)
    omission_detected = contract.functions.omission_detected().call({"from": user_addr})
    print(omission_detected)
    print("[billboard] gasUsed", ge)
    assert omission_detected


def user_verify_omission_data(user_num, audit_num=None):
    user_num = int(user_num)+1
    user_addr, _ = get_account(user_num)
    w3 = setup_w3()
    contract = get_contract(w3)
    if audit_num is None:
        audit_num = contract.functions.last_audit_num().call({"from": user_addr})
    audit_num = int(audit_num)
    ge = send_tx(w3, contract.functions.prove_omission_data(user_addr, audit_num), user_addr)
    omission_detected = contract.functions.omission_detected().call({"from": user_addr})
    print(omission_detected)
    print("[billboard] gasUsed", ge)
    assert omission_detected


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