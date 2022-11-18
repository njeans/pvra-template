import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from http import HTTPStatus


from web3 import Web3

from constants import *
from utils import *
from crypto import *

import application
import billboard as bb
import enclave
import auditee
import merkletree
import user as user_lib


def print_vv(*args):
    if verbose >= 2:
        print(ADMINc+"[admin.py]", *args)
        print(NOCOLOR, end="")


def print_v(*args):
    if verbose >= 1:
        print(ADMINc+"[admin.py]", *args)
        print(NOCOLOR, end="")


def print_(*args, c=ADMINc):
    if c == ERRORc:
        print(c+"[admin.py] ERROR:", *args)
    else:
        print(c+"[admin.py]", *args)
    print(NOCOLOR, end="")


def AdminHandler(admin_lib):
    class Handler(BaseHTTPRequestHandler):

        error_content_type = "application/json"

        def __init__(self, *args, **kwargs):
            self.admin_lib = admin_lib
            super(Handler, self).__init__(*args, **kwargs)

        def do_POST(self):
            query_components = parse_qs(urlparse(self.path).query)
            print_vv(f"serving POST request for {self.path}")
            res = {}
            if "/command" in self.path:
                command = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                print_vv("command", command)
                res["msg"] = ""
                res["sig"] = ""
                cmd, pubk = bytes.fromhex(command["eCMD"]), bytes.fromhex(command["pubkeyCMD"])
                if 'mode' in query_components and \
                        OMIT_SIG in query_components['mode'] or \
                        OMIT_DATA in query_components['mode'] or \
                        INCL_DATA in query_components['mode']:
                    print_v("omitting data but returning signature")
                else:
                    resp, sig = self.admin_lib._send_command(cmd, pubk, command["seq"])
                    res["msg"] = resp.hex()
                    res["sig"] = sig.hex() #todo
                conf, conf_sig = self.admin_lib._sign_confirmation(pubk, cmd)
                res["msg_conf"] = conf
                res["sig_conf"] = conf_sig
                print_vv(f"server returning {res}")
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(res), "utf-8"))
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "path not found (%r)" % self.path)

        def send_error(self, code, message=None, explain=None):
            try:
                shortmsg, longmsg = self.responses[code]
            except KeyError:
                shortmsg, longmsg = '???', '???'
            if message is None:
                message = shortmsg
            if explain is None:
                explain = longmsg
            self.log_error("code %d, message %s", code, message)
            self.send_response(code, message)
            self.send_header('Connection', 'close')

            # Message body is omitted for cases described in:
            #  - RFC7230: 3.3. 1xx, 204(No Content), 304(Not Modified)
            #  - RFC7231: 6.3.6. 205(Reset Content)
            body = None
            if (code >= 200 and
                    code not in (HTTPStatus.NO_CONTENT,
                                 HTTPStatus.RESET_CONTENT,
                                 HTTPStatus.NOT_MODIFIED)):
                # HTML encode to prevent Cross Site Scripting attacks
                # (see bug #1100201)
                content = {'code': code, 'message': message, 'explain': explain}
                body = json.dumps(content)
                self.send_header("Content-Type", self.error_content_type)
                self.send_header('Content-Length', str(len(body)))
            self.end_headers()

            if self.command != 'HEAD' and body:
                self.wfile.write(body)

        def log_message(self, format, *args):
            print_vv(format%args)

        def log_error(self, format, *args):
            print_(format%args, c=ERRORc)
    return Handler


class Admin:
    def __init__(self, w3, bb_info):
        self.address, self.public_key, self.secret_key = bb_info
        print_vv(f"initialize Admin with address {print_hex_trunc(self.address)} using port {ADMIN_PORT}")
        server_address = ('localhost', ADMIN_PORT)
        self.httpd = HTTPServer(server_address, AdminHandler(self))
        self.w3 = w3
        self.state_counter = 0
        self.state_counter_lock = threading.Lock()
        self.audit_num = 0
        self._init_enclave()
        self._init_contract()
        self.server_thread = threading.Thread(None, self.httpd.serve_forever)
        self.admin_user = user_lib.User(-1, bb_info, self.w3, self.contract)
        self.admin_user.print_ = print_
        self.admin_user.print_v = print_v
        self.admin_user.print_vv = print_vv

    def start_server(self):
        print_(f"server starting on port {ADMIN_PORT}")
        # self.httpd.serve_forever()
        self.server_thread.start()

    def shutdown_server(self):
        print_v(f"server shutting down")
        self.httpd.shutdown()
        self.server_thread.join() # todo remove?

    def audit(self, mode=INCL_DATA):
        print_v(f"checkpointing audit {self.audit_num+1}") #todo bb return audit num from audit_start
        gas = bb.send_tx(self.w3, self.contract.functions.audit_start(), user_addr=self.address)
        if OMIT_SIG not in str(mode) and \
            INCL_SIG not in str(mode) and \
            INCL_DATA not in str(mode):
            print_v(f"not getting data from bulletin board {mode}")
        else:
            bb_data = self._get_bb_data(self.audit_num+1)
            for data in bb_data:
                pubkey, cmd, seq = data
                addr = convert_publickey_address(pubkey)
                if type(mode) == dict and pubkey in mode:
                    m = mode[pubkey]
                else:
                    m = mode
                if m not in [OMIT_SIG, OMIT_DATA]:
                    print_v(f"posting data from bulletin board for user address {print_hex_trunc(addr)}")
                    self._send_command(cmd, pubkey, seq)

        # self.state_counter_lock.acquire()  # todo audit log command should use state counter?
        audit_log_raw, audit_log_sig = enclave.auditlogPVRA(self.state_counter)
        # self.state_counter += 1
        # self.state_counter_lock.release()

        audit_log_offset = 0
        if MERKLE():
            audit_log_offset, leaves, nodes = self._parse_merkle_tree(audit_log_raw)
        audit_num, included_addr, included_hashes, audit_seq = self._parse_audit_log(audit_log_raw[audit_log_offset:])
        assert audit_num == self.audit_num+1
        if MERKLE():
            print_vv(f"posting merkle tree audit log for: {audit_num}")
            gas += bb.send_tx(self.w3, self.contract.functions.audit_end_merkle(audit_log_sig, included_addr, included_hashes, audit_seq, leaves, nodes), user_addr=self.address)
            print_vv(f"contract.functions.audit_start + audit_end_merkle: gasUsed {gas}")
        else:
            print_vv(f"posting audit log for: {audit_num}")
            gas += bb.send_tx(self.w3, self.contract.functions.audit_end(audit_log_sig, included_addr, included_hashes, audit_seq), user_addr=self.address)
            print_vv(f"contract.functions.audit_start + audit_end: gasUsed {gas}")
        self.audit_num = audit_num

        # tmp_byte = self.contract.functions.tmp_byte().call({"from": self.address})
        # tmp_hash = self.contract.functions.tmp_hash().call({"from": self.address})
        # tmp_addr = self.contract.functions.tmp_addr().call({"from": self.address})
        # ee = self.contract.functions.enclave_address().call({"from": self.address})
        # print("tmp_byte", tmp_byte.hex())
        # print("tmp_hash", tmp_hash.hex())
        # print("tmp_addr", tmp_addr)
        # print("enclave_address", ee)
        # assert ee == tmp_addr

    def _init_enclave(self):
        enclave.initPvra()
        # auditee.verify_ias_report()
        res = verify_secp256k1_path(SIGN_KEY_PATH, ENCLAVE_PUBLIC_KEY_PATH, ENCLAVE_PUBLIC_KEY_SIG_PATH)
        print_v(f"verifying signed encryption key: {res}")
        ENCLAVE_PUBLIC_KEY()

    def _init_contract(self):
        with open(USER_LIST_SIG_PATH, "rb") as f:
            signature = f.read()
        with open(USER_LIST_PATH) as f:
            data = f.read().split("\n")
        user_addresses = [convert_publickey_address(x) for x in data]
        address_data = b"".join(map(get_packed_address, user_addresses))
        res = recover_eth_data(address_data, signature, publickey=ENCLAVE_PUBLIC_KEY())
        print_v(f"verifying signed user address list: {res}")
        assert res
        contract_address, self.contract, contract_id = bb.deploy_contract(self.w3,  self.address)
        print_vv(f"initializing contract with users: {user_addresses}")
        ge = bb.send_tx(self.w3, self.contract.functions.initialize(user_addresses, signature), self.address)
        print_vv("contract.functions.initialize: gasUsed", ge)
        initialized = self.contract.functions.initialized().call({"from": self.address})
        assert initialized

    def _send_command(self, cmd, pubkey, seq):
        self.state_counter_lock.acquire()
        resp, sig = enclave.commandPVRA(self.state_counter, cmd, pubkey, seq)
        self.state_counter += 1
        self.state_counter_lock.release()
        return resp, sig

    def _get_bb_data(self, audit_num):
        user_datas = self.contract.functions.get_all_user_data(audit_num).call({"from": self.address})
        encrypted_data = [(x[0], x[2], x[3]) for x in user_datas]
        return encrypted_data

    def _sign_confirmation(self, user_pubkey, user_cmd):
        last_audit_num = self.contract.functions.audit_num().call({"from": self.address})
        audit_num = last_audit_num+1
        user_addr = bytes.fromhex(convert_publickey_address(user_pubkey)[2:]) #get_packed_address(convert_publickey_address(user_pubkey))
        user_cmd_hash = sha3(user_cmd)
        confirmation = bytes(str(audit_num), "utf-8") + user_addr + user_cmd_hash #todo change to 32 bit audit num
        sig = sign_eth_data(self.secret_key, confirmation)
        return confirmation.hex(), sig

    def _parse_merkle_tree(self, audit_log_raw):
        nodes, leaves, audit_log_offset = merkletree.parse_tree(audit_log_raw)
        merkletree.check_tree(nodes, leaves)
        print_fun = lambda x: print_hex_trunc(x.hex())
        mt = "\n"+merkletree.print_tree(nodes, leaves, str_node=print_fun, str_leaf=print_fun)
        print_vv(f"merkle tree:{mt}")
        return audit_log_offset, leaves, nodes

    def _parse_audit_log(self, audit_log_raw):
        audit_num = int.from_bytes(audit_log_raw[:U64_SIZE], "big")
        num_entries = int((len(audit_log_raw) - U64_SIZE)/(PACKED_ADDR_SIZE+HASH_SIZE+U64_SIZE))
        audit_log_offset = U64_SIZE
        audit_log_offset_addr = U64_SIZE + PACKED_ADDR_SIZE * num_entries
        audit_log_offset_seq = U64_SIZE + (PACKED_ADDR_SIZE + HASH_SIZE) * num_entries
        audit_data_address = [get_address_from_packed(audit_log_raw[i:i+PACKED_ADDR_SIZE]) for i in range(audit_log_offset, audit_log_offset_addr, PACKED_ADDR_SIZE)]
        audit_data_hashes = [audit_log_raw[i:i+HASH_SIZE] for i in range(audit_log_offset_addr, audit_log_offset_seq, HASH_SIZE)]
        audit_seq = [int.from_bytes(audit_log_raw[i:i+U64_SIZE], "big") for i in range(audit_log_offset_seq, len(audit_log_raw), U64_SIZE)]
        assert len(audit_data_hashes) == len(audit_data_address)
        assert len(audit_data_hashes) == len(audit_seq)
        al = "\n"+"\n".join([f"{audit_data_address[i]}:[seq: {audit_seq[i]}]->{print_hex_trunc(audit_data_hashes[i].hex())}" for i in range(num_entries)])
        print_vv(f"audit_log for audit_num {audit_num}: len: {num_entries}{al}")
        return audit_num, audit_data_address, audit_data_hashes, audit_seq









