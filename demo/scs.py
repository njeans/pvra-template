import requests
import sys
import base64
import time
import ccf.receipt

from constants import *
from utils import sha256
from crypto import verify_x509_data


def setup_scs():
    with open(SEAL_STATE_PATH, "rb") as f:
        seal_state = f.read()
    seal_state_hash = sha256(seal_state)
    headers = {"Content-Type": "application/json"}
    req_data = {"hash": seal_state_hash.hex()}

    cmd_url = f"{CCF_URL}/app/setup/{CCF_USERID}"
    print_vv(f"Sending post request to ccf node at {cmd_url} with data {req_data} ", n="scs.py")
    req = requests.post(cmd_url, json=req_data, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
    if req.status_code != 204:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n="scs.py")
        exit(req.status_code)


def get_ft(full_cmd):
    if isinstance(full_cmd, str):
        full_cmd = bytes.fromhex(full_cmd)
    with open(SEAL_STATE_PATH, "rb") as f:
        seal_state = f.read()
    scs_hash = sha256(seal_state)

    headers = {"Content-Type": "application/json"}
    req_data = {"hash": scs_hash.hex()}
    cmd_url = f"{CCF_URL}/app/scs/{CCF_USERID}"

    print_vv(f"Sending post request to ccf node at {cmd_url} with data {req_data} ", n="scs.py")

    req = requests.post(cmd_url, json=req_data, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
    if req.status_code != 200:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n="scs.py")
        exit(req.status_code)
    resp = req.json()
    with open(FT_PATH, "w") as f:
        f.write(resp["ft"])
    
    tx_id = req.headers["x-ms-ccf-transaction-id"]
    print(tx_id)
    return tx_id


def get_ft_sig(tx_id):

    headers = {"Content-Type": "application/json"}
    params = {"transaction_id": tx_id}
    cmd_url = f"{CCF_URL}/app/receipt/{CCF_USERID}"

    print_vv(f"Sending get request to ccf node at {cmd_url} with params {params} ", n="scs.py")

    req = requests.get(cmd_url, params=params, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))

    max_retry = 3
    retry_count = 0
    while req.status_code == 202 and retry_count < max_retry:  # must wait for transaction to be committed
        print_vv(f"Retrying {retry_count} {cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n="scs.py")
        time.sleep(3)
        req = requests.get(cmd_url, params=params, headers=headers, verify=CCF_SERVICE_CERT_PATH, cert=(CCF_USER_CERT_PATH, CCF_USER_KEY_PATH))
        retry_count+=1
    
    if req.status_code != 200:
        print_(f"{cmd_url} status_code: {req.status_code} content: {req.text}", c=ERRORc, n="scs.py")
        exit(req.status_code)
    resp = req.json()
    ft = bytes.fromhex(resp["leaf_components"]["hash"])
    commit_evidence_digest = sha256(resp["leaf_components"]["commit_evidence"].encode())
    write_set_digest = bytes.fromhex(resp["leaf_components"]["write_set_digest"])
    leaf = (sha256(write_set_digest + commit_evidence_digest + ft).hex())
    root = bytes.fromhex(ccf.receipt.root(leaf, resp["proof"]))
    node_cert = resp["cert"].encode()
    res = verify_x509_data(root, base64.b64decode(resp["signature"]), node_cert)
    print_v(f"verifying freshness tag signature: {res}", n="scs.py")
    assert res
    with open(FT_SIG_PATH, "wb") as f:
        f.write(root)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])