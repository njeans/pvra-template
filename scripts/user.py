import json
import requests

from utils import *
from constants import *
from crypto import *
import billboard as bb
from application import format_command


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

    def __init__(self, user_num, bb_info, w3, contract):
        self.user_num = user_num
        self.address, self.public_key, self.secret_key = bb_info
        self.w3 = w3
        self.seq_num = 0 #todo use in encrypt command
        self.contract = contract
        self.print_v(f"initialize User {user_num} with address {print_hex_trunc(self.address)} and public key {print_hex_trunc(self.public_key)}")
        self.admin_addr = self.contract.functions.admin_addr().call({"from": self.address})
        self.enclave_addr = self.contract.functions.enclave_address().call({"from": self.address})
        self.sent_commands = {}

    def verify_bb_info(self):
        '''
            check that I am included in the user list on the bb
        '''
        self._verify_ias()
        self.print_v(f"verifying user initialization data correct")
        user_info = self.contract.functions.get_user(self.address, 0).call({"from": self.address})
        assert user_info[0] == self.address
        assert user_info[1] == 0  # last_audit_num
        assert user_info[2] == b''  # user_data # todo add parse_bb_user_info function to util?

    def encrypt_data(self, data):
        self.print_vv(f"encrypting user data {data}")  # todo add data print function to application.py ?
        shared_key = derive_key_aes(self.secret_key, ENCLAVE_PUBLIC_KEY())
        encrypted_data = self._encrypt(shared_key, format_command(data))
        self.seq_num += 1
        return encrypted_data

    def send_data(self, encrypted_user_data, mode=INCL_SIG):
        ok, res = self.send_data_admin(encrypted_user_data, mode)
        if not ok:
            self.print_v(f"admin confirmation signature verification failed [{res}] posting to bulletin board")
            self.send_data_bb(encrypted_user_data)
        else:
            self.send_data_bb(encrypted_user_data, mode)
        return res

    def send_data_admin(self, encrypted_user_data, mode=INCL_SIG):
        if mode in [OMIT_DATA, INCL_DATA]:
            return True, ""
        self.print_v(f"sending encrypted user data to bulletin board {print_hex_trunc(encrypted_user_data)}")
        params = {"mode": mode}
        headers = {"Content-Type": "application/json"}
        cmd_data = {"eCMD": encrypted_user_data.hex(), "pubkeyCMD": self.public_key.hex()}
        self.print_vv(f"Sending command to server {cmd_data} with pubkey {print_hex_trunc(self.public_key)}")
        cmd_url = f"http://{ADMIN_IP}:{ADMIN_PORT}/command"
        req = requests.post(cmd_url, json=cmd_data, headers=headers, params=params)
        if req.status_code != 200:
            self.print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc)
            exit(req.status_code)
        resp = req.json()
        self.print_v(f"server response {resp}")
        msg = bytes.fromhex(resp["msg"])
        sig = bytes.fromhex(resp["sig"])
        res_enclave = True#recover_eth_data(msg, sig, address=self.enclave_addr) todo
        msg_conf = bytes.fromhex(resp["msg_conf"])
        sig_conf = bytes.fromhex(resp["sig_conf"])
        res_admin, conf_data = self._verify_confirmation(msg_conf, sig_conf, encrypted_user_data)
        self.print_v(f"admin cResponse {msg} enclave cResponse verify {res_enclave} admin confirmation verify {res_admin}: {conf_data}")
        if mode not in [INCL_SIG, OMIT_SIG]:
            assert res_enclave
        self.sent_commands[encrypted_user_data.hex()] = {"msg_conf": conf_data, "sig_conf": sig_conf}
        return res_admin, msg

    def send_data_bb(self, encrypted_user_data, mode=INCL_DATA):
        if mode in [OMIT_SIG, INCL_SIG]:
            return
        self.print_v(f"sending encrypted user data to bulletin board {print_hex_trunc(encrypted_user_data)}")
        gas = bb.send_tx(self.w3, self.contract.functions.add_user_data(encrypted_user_data), self.address)
        user_info = self.contract.functions.get_user(self.address, 0).call({"from": self.address})
        assert user_info[0] == self.address
        # assert user_info[1] == self.audit_num  # last_audit_num todo get last_audit_num to compare?
        assert user_info[2] == encrypted_user_data  # user_data
        self.sent_commands[encrypted_user_data.hex()]["audit_num"] = user_info[1]
        self.print_vv(f"contract.functions.add_user_data: gasUsed {gas}")

    def check_leaf(self, leaf):
        bb_leaf = b''  # todo get from call data 0.0
        return leaf == bb_leaf

    def verify_omission(self, encrypted_user_data, mode):
        if mode not in [OMIT_DATA, OMIT_SIG]:
            return
        res = self.sent_commands[encrypted_user_data.hex()]
        if mode == OMIT_DATA:
            audit_num = res["audit_num"]
            gas = bb.send_tx(self.w3, self.contract.functions.verify_omission_data(self.address, audit_num), self.address)
            omission_detected = self.contract.functions.omission_detected().call({"from": self.address})
            self.print_v(f"verifying proof of omission with data for audit_num {audit_num}: omission_detected {omission_detected}")
            self.print_vv(f"contract.functions.verify_omission_data: gasUsed {gas}")
        else:
            audit_num, listed_address, listed_data_hash = res["msg_conf"]
            sig = res["sig_conf"]
            gas = bb.send_tx(self.w3, self.contract.functions.verify_omission_sig(listed_address, audit_num, listed_data_hash, sig), self.address)
            omission_detected = self.contract.functions.omission_detected().call({"from": self.address})
            self.print_v(f"verifying proof of omission with admin signature for audit_num {audit_num}: omission_detected {omission_detected}")
            self.print_vv(f"contract.functions.verify_omission_sig: gasUsed {gas}")
        assert omission_detected

    def _verify_ias(self):
        ias_report = self.contract.functions.ias_report().call({"from": self.address})
        self.print_v(f"verifying ias report")
        self.print_vv(f"{json.dumps(str(ias_report), indent=2)}")
        # auditee.verify_ias_report()

    def _verify_confirmation(self, msg, sig, cmd):
        len_audit_num = len(msg) - 32 - 32  # todo change to 32 bit audit num
        listed_audit_num = int(msg[:len_audit_num])
        last_audit_num = self.contract.functions.audit_num().call({"from": self.address})
        listed_address = get_address_from_packed(msg[len_audit_num:len_audit_num+32])
        listed_data_hash = msg[len_audit_num+32:]
        if listed_audit_num not in [last_audit_num+1, last_audit_num]:
            return False, f"audit_num {listed_audit_num} not in {[last_audit_num, last_audit_num+1]}"
        if listed_address != self.address:
            return False, f"address {print_hex_trunc(listed_address)} != {print_hex_trunc(self.address)}"
        correct_hash = sha3(cmd)
        if listed_data_hash != correct_hash:
            return False, f"data hash {print_hex_trunc(listed_data_hash)} != {print_hex_trunc(correct_hash)}"
        if not recover_eth_data(msg, sig, address=self.admin_addr):
            return False, f"signature verification failure"
        return True, (listed_audit_num, listed_address, listed_data_hash)

    def _encrypt(self, key, data):
        return encrypt_aes(key, data)

    def print_(self, *args, c=None):
        print_(*args, c=c, u=self.user_num)

    def print_v(self, *args):
        print_v(*args, u=self.user_num)

    def print_vv(self, *args):
        print_vv(*args, u=self.user_num)