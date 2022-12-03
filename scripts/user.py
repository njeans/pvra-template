import json
import requests

import web3

from utils import *
from constants import *
from crypto import *
import billboard as bb
from application import format_command
import application as app
import merkletree

def print_vv(*args, u=0):
    if verbose >= 2:
        print(f"{USERc[u%len(USERc)]}[user.py] {u}", *args)
        print(NOCOLOR, end="")


def print_v(*args, u=0):
    if verbose >= 1:
        print(f"{USERc[u%len(USERc)]}[user.py] {u}", *args)
        print(NOCOLOR, end="")


def print_(*args, c=None, u=0):
    if c == ERRORc:
        print(f"{c}[user.py] {u} ERROR:", *args)
    elif c is None:
        print(f"{USERc[u]}[user.py] {u}", *args)
    else:
        print(f"{c}[user.py] {u}", *args)
    print(NOCOLOR, end="")


class User:

    def __init__(self, uidx, bb_info, w3, contract):
        self.uidx = uidx
        self.address, self.public_key, self.secret_key = bb_info
        self.w3 = w3
        self.seq_num = 0
        self.contract = contract
        self.print_v(f"initialize User {uidx} with address {print_hex_trunc(self.address)} and public key {print_hex_trunc(self.public_key)}")
        self.admin_addr = self.contract.functions.admin_addr().call({"from": self.address})
        import constants
        self.enclave_addr = self.contract.functions.enclave_address().call({"from": self.address})
        self.sent_commands = {}

    def verify_bb_info(self):
        '''
            check that I am included in the user list on the bb
        '''
        self._verify_ias()
        self.print_v(f"verifying user initialization data correct")
        user_info = self.contract.functions.get_user(self.address, 0).call({"from": self.address})
        # assert user_info[0] == self.public_key
        assert user_info[1] == 0  # last_audit_num
        assert user_info[2] == b''  # user_data # todo add parse_bb_user_info function to util?

    def encrypt_data(self, data):
        self.print_vv(f"encrypting user data {data}")
        shared_key = derive_key_aes(self.secret_key, ENCLAVE_PUBLIC_KEY())
        encrypted_data = self._encrypt(shared_key, format_command(data))
        self.seq_num += 1
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        # self.print_vv(f"decrypting data {encrypted_data.hex()}")
        shared_key = derive_key_aes(self.secret_key, ENCLAVE_PUBLIC_KEY())
        data = self._decrypt(shared_key, encrypted_data)
        return data

    def send_data(self, encrypted_user_data, mode=INCL_SIG, seq=-1):
        if seq == -1:
            self.print_vv("send_data using calculated seq_num", self.seq_num)
        else:
            self.print_vv("send_data using seq_num", seq)
            self.seq_num = seq
        ok, res = self.send_data_admin(encrypted_user_data, self.seq_num, mode)
        if not ok:
            self.print_v(f"admin confirmation signature verification failed [{res}] posting to bulletin board")
            self.send_data_bb(encrypted_user_data, self.seq_num)
        else:
            self.send_data_bb(encrypted_user_data, self.seq_num, mode)

        return res

    def send_data_admin(self, encrypted_user_data, seq=-1, mode=INCL_SIG):
        if mode in [OMIT_DATA, INCL_DATA]:
            return True, ""
        if seq == -1:
            self.print_vv("send_data_admin using calculated seq_num", self.seq_num)
        else:
            self.print_vv("send_data_admin using seq_num", seq)
            self.seq_num = seq

        self.print_v(f"sending encrypted user data to admin {print_hex_trunc(encrypted_user_data)}")
        params = {"mode": mode}
        headers = {"Content-Type": "application/json"}
        cmd_data = {"eCMD": encrypted_user_data.hex(), "pubkeyCMD": self.public_key.hex(), "seq": self.seq_num}
        self.print_vv(f"Sending command to server {cmd_data} with pubkey {print_hex_trunc(self.public_key)}")
        cmd_url = f"http://{ADMIN_IP}:{ADMIN_PORT}/command"
        req = requests.post(cmd_url, json=cmd_data, headers=headers, params=params)
        if req.status_code != 200:
            self.print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc)
            exit(req.status_code)
        resp = req.json()
        self.print_v(f"server response {resp}")
        msg = bytes.fromhex(resp["msg"])
        msg_str = msg
        sig = bytes.fromhex(resp["sig"])
        if msg != b'':
            msg = self.decrypt_data(msg)
            res_enclave = verify_secp256k1_data(ENCLAVE_PUBLIC_KEY(), msg, sig)
            msg_str = app.print_cResponse(msg)
        else:
            res_enclave = False
        msg_conf = bytes.fromhex(resp["msg_conf"])
        sig_conf = bytes.fromhex(resp["sig_conf"])
        res_admin, conf_data = self._verify_confirmation(msg_conf, sig_conf, encrypted_user_data)
        if res_admin:
            self.print_v(f"enclave cResponse verify {res_enclave} admin confirmation verify {res_admin} decrypted cResponse {msg_str}")
        else:
            self.print_v(f"enclave cResponse verify {res_enclave} admin confirmation verify {res_admin}:{conf_data} decrypted cResponse {msg_str}")
        if mode not in [INCL_SIG, OMIT_SIG]:
            assert res_enclave
        self.sent_commands[encrypted_user_data.hex()] = {"msg_conf": conf_data, "sig_conf": sig_conf}
        return res_admin, msg

    def send_data_bb(self, encrypted_user_data, seq=-1, mode=INCL_DATA):
        if mode in [OMIT_SIG, INCL_SIG]:
            return
        if seq == -1:
            self.print_vv("send_data_bb using calculated seq_num", self.seq_num)
        else:
            self.print_vv("send_data_bb using seq_num", seq)
            self.seq_num = seq

        self.print_v(f"sending encrypted user data to bulletin board {print_hex_trunc(encrypted_user_data)} with pubkey {print_hex_trunc(self.public_key)}")
        gas = bb.send_tx(self.w3, self.contract.functions.add_user_data(self.public_key, encrypted_user_data, self.seq_num), self.address)

        user_info = self.contract.functions.get_user(self.address, 0).call({"from": self.address})
        assert user_info[0] == self.public_key
        # assert user_info[1] == self.audit_num  # last_audit_num todo get last_audit_num to compare?
        assert user_info[2] == encrypted_user_data  # user_data
        assert user_info[3] == self.seq_num  # last_seq_num
        if encrypted_user_data.hex() in self.sent_commands:
            self.sent_commands[encrypted_user_data.hex()]["audit_num"] = user_info[1]
        else:
            self.sent_commands[encrypted_user_data.hex()] = {"audit_num": user_info[1]}
        self.print_vv(f"contract.functions.add_user_data: gasUsed {gas}")

    def get_leaf(self, audit_num):
        merkle_root = self.contract.functions.get_audit_merkle_root(audit_num).call({"from": self.address})
        block_num = self.contract.functions.get_audit_block_num(audit_num).call({"from": self.address})
        block = self.w3.eth.getBlock(block_num)
        bb_leaf = {}
        for tx_hash in block["transactions"]:
            tx = self.w3.eth.get_transaction(tx_hash)
            if tx["from"] != self.admin_addr:
                continue
            if tx["to"] != self.contract.address:
                continue
            func_obj, func_params = self.contract.decode_function_input(tx["input"])
            if "audit_end" not in str(func_obj):
                continue
            leaves = func_params["leaves"]
            nodes = func_params["proof"]
            merkletree.check_tree(nodes, leaves)
            assert nodes[len(nodes)-1] == merkle_root
            for lf in leaves:
                try:
                    dec_leaf = self.decrypt_data(lf)
                except:
                    continue
                leaf = app.get_leaf(dec_leaf)
                if leaf["uidx"] == self.uidx:
                    bb_leaf = leaf
                    break
        return bb_leaf

    def check_leaf(self, expected_leaf, audit_num):
        leaf = self.get_leaf(audit_num)
        return expected_leaf == leaf

    def verify_omission(self, encrypted_user_data, mode):
        res = self.sent_commands[encrypted_user_data.hex()]
        omission_detected = False
        if mode in [OMIT_DATA, INCL_DATA]:
            audit_num = res["audit_num"]
            self.print_vv(f"verifying proof of omission with data for audit_num {audit_num}")
            try:
                gas = bb.send_tx(self.w3, self.contract.functions.verify_omission_data(self.address, audit_num), self.address)
                self.print_vv(f"contract.functions.verify_omission_data: gasUsed {gas}")
                omission_detected = self.contract.functions.omission_detected().call({"from": self.address})
            except web3.exceptions.ContractLogicError as e:
                assert "data hashes match" in str(e)
            self.print_v(f"verifying proof of omission with data for audit_num {audit_num}: omission_detected {omission_detected}")

        else:
            audit_num, listed_address, listed_data_hash = res["msg_conf"]
            self.print_vv(f"verifying proof of omission with admin signature for audit_num {audit_num}")
            sig = res["sig_conf"]
            try:
                gas = bb.send_tx(self.w3, self.contract.functions.verify_omission_sig(listed_address, audit_num, listed_data_hash, sig), self.address)
                self.print_vv(f"contract.functions.verify_omission_sig: gasUsed {gas}")
                omission_detected = self.contract.functions.omission_detected().call({"from": self.address})
            except web3.exceptions.ContractLogicError as e:
                assert "data hashes match" in str(e)
            self.print_v(f"verifying proof of omission with admin signature for audit_num {audit_num}: omission_detected {omission_detected}")
        if mode in [OMIT_SIG, OMIT_DATA]:
            assert omission_detected
        else:
            assert omission_detected == False

    def _verify_ias(self):
        ias_report = self.contract.functions.ias_report().call({"from": self.address})
        self.print_v(f"verifying ias report")
        self.print_vv(f"{json.dumps(str(ias_report), indent=2)}")
        # auditee.verify_ias_report()

    def _verify_confirmation(self, msg, sig, cmd):
        len_audit_num = len(msg) - 20 - 32  # todo change to 32 bit audit num
        listed_audit_num = int(msg[:len_audit_num])
        last_audit_num = self.contract.functions.audit_num().call({"from": self.address})
        listed_address = msg[len_audit_num:len_audit_num+20] #get_address_from_packed(msg[len_audit_num:len_audit_num+32])
        listed_data_hash = msg[len_audit_num+20:]
        if listed_audit_num not in [last_audit_num+1, last_audit_num]:
            return False, f"audit_num {listed_audit_num} not in {[last_audit_num, last_audit_num+1]}"
        if "0x"+listed_address.hex() != self.address.lower():
            return False, f"address {print_hex_trunc(listed_address)} != {print_hex_trunc(self.address.lower())}"
        correct_hash = sha3(cmd)
        if listed_data_hash != correct_hash:
            return False, f"data hash {print_hex_trunc(listed_data_hash)} != {print_hex_trunc(correct_hash)}"
        if not recover_eth_data(msg, sig, address=self.admin_addr):
            return False, f"signature verification failure"
        return True, (listed_audit_num, listed_address, listed_data_hash)

    def _encrypt(self, key, data):
        return encrypt_aes(key, data)

    def _decrypt(self, key, data):
        if data[:12+16] != bytes([0 for _ in range(12+16)]):
            return decrypt_aes(key, data)
        else:
            return data[12+16:]

    def print_(self, *args, c=None):
        print_(*args, c=c, u=self.uidx)

    def print_v(self, *args):
        print_v(*args, u=self.uidx)

    def print_vv(self, *args):
        print_vv(*args, u=self.uidx)