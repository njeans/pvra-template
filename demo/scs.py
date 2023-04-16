import sys
import base64
import time
import ctypes
import requests
import ccf.receipt

from constants import *
from utils import sha256
from crypto import verify_x509_data

FILENAME="scs.py"

def setup_scs():
    seal_state_hash = bytes([0 for _ in range(32)])
    headers = {"Content-Type": "application/json"}
    req_data = {"hash": seal_state_hash.hex()}

    cmd_url = f"{CCF_URL}/app/setup/{CCF_USERID}"
    print_vv(f"Sending post request to ccf node at {cmd_url} with data {req_data} ", n=FILENAME)
    req = requests.post(cmd_url, json=req_data, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
    if req.status_code != 204:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n=FILENAME)
        exit(req.status_code)

def reset_scs():
    headers = {"Content-Type": "application/json"}
    cmd_url = f"{CCF_URL}/app/reset/{CCF_USERID}"
    print_(f"Sending put request to ccf node at {cmd_url} with priveledged member credentials", n=FILENAME)
    req = requests.put(cmd_url, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_MEMBER_CERT_PATH, CCF_MEMBER_KEY_PATH))
    if req.status_code != 202:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n=FILENAME)
        exit(req.status_code)

def get_ft(full_cmd):
    if isinstance(full_cmd, str):
        full_cmd = bytes.fromhex(full_cmd)
    with open(SEAL_STATE_PATH, "rb") as f:
        seal_state = f.read()
    scs_hash = sha256(seal_state + full_cmd)

    headers = {"Content-Type": "application/json"}
    req_data = {"hash": scs_hash.hex()}
    cmd_url = f"{CCF_URL}/app/scs/{CCF_USERID}"

    print_vv(f"Sending post request to ccf node at {cmd_url} with data {req_data} ", n=FILENAME)

    req = requests.post(cmd_url, json=req_data, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
    if req.status_code != 200:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n=FILENAME)
        exit(req.status_code)
    resp = req.json()
    with open(FT_PATH, "wb") as f:
        f.write(bytes.fromhex(resp["ft"]))
    
    tx_id = req.headers["x-ms-ccf-transaction-id"]
    return tx_id


def get_ft_sig(tx_id):

    headers = {"Content-Type": "application/json"}
    params = {"transaction_id": tx_id}
    cmd_url = f"{CCF_URL}/app/receipt/{CCF_USERID}"

    print_vv(f"Sending get request to ccf node at {cmd_url} with params {params} ", n=FILENAME)

    req = requests.get(cmd_url, params=params, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))

    max_retry = 10
    retry_count = 0
    while req.status_code == 202 and retry_count < max_retry:  # must wait for transaction to be committed
        if retry_count > 0: #first call usually fails
            print_vv(f"Retrying {retry_count} {cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n=FILENAME)
        time.sleep(1)
        req = requests.get(cmd_url, params=params, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
        retry_count+=1
    
    if req.status_code != 200:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n=FILENAME)
        exit(req.status_code)
    resp = req.json()
    ft = bytes.fromhex(resp["leaf_components"]["hash"])
    with open(FT_PATH, "rb") as f:
        saved_ft = f.read()
        assert ft == saved_ft
    commit_evidence_digest = sha256(resp["leaf_components"]["commit_evidence"].encode())
    write_set_digest = bytes.fromhex(resp["leaf_components"]["write_set_digest"])
    leaf = (sha256(write_set_digest + commit_evidence_digest + ft).hex())
    root = bytes.fromhex(ccf.receipt.root(leaf, resp["proof"]))
    node_cert = resp["cert"].encode()
    signature = base64.b64decode(resp["signature"])
    res = verify_x509_data(root, base64.b64decode(resp["signature"]), node_cert)
    print_v(f"verifying freshness tag signature: {res}", n=FILENAME)
    assert res
    ce = U8ArrHash.from_buffer_copy(commit_evidence_digest)
    ws = U8ArrHash.from_buffer_copy(write_set_digest)
    fte = U8ArrHash.from_buffer_copy(ft)
    evidence = bytes(ccf_proof(ce, ws, fte, len(resp["proof"])))
    for p in resp["proof"]:
        if "left" in p:
            pd = U8ArrHash.from_buffer_copy(bytes.fromhex(p["left"]))
            evidence += bytes(ccf_node("left" in p, pd))
        else:
            pd = U8ArrHash.from_buffer_copy(bytes.fromhex(p["right"]))
            evidence += bytes(ccf_node("left" in p, pd))

    with open(FT_EVD_PATH, "wb") as f:
        f.write(evidence)
    with open(FT_SIG_PATH, "wb") as f:
        f.write(signature)

U8ArrHash = ctypes.c_uint8 * HASH_SIZE

class ccf_node(ctypes.Structure):
    _fields_ = [('is_left', ctypes.c_bool),
                ('data', U8ArrHash)]


class ccf_proof(ctypes.Structure):
    _fields_ = [('commit_evidence_digest', U8ArrHash),
                ('write_set_digest', U8ArrHash),
                ('FT', U8ArrHash),
                ('proof_len', ctypes.c_uint64)]


if __name__ == '__main__':
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])