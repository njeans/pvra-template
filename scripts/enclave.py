import json
import subprocess

from constants import *


def print_vv(*args, c=""):
    if verbose >= 2:
        print(c+"[enclave.py]", *args)
        print(NOCOLOR, end="")

def print_(*args, c=""):
    print(c+"[enclave.py]", *args)
    print(NOCOLOR, end="")


def initPvra():
    init_cmd = APP_PATH + " --initPVRA" + \
                " --enclave-path " + SIGNED_ENCLAVE_PATH + \
               " --sealedState " + SEAL_STATE_PATH + \
               " --quotefile " + QUOTE_FILE_PATH + \
               " --signature " + ENCLAVE_PUBLIC_KEY_SIG_PATH + \
               " --userpubkeys " + USER_LIST_PATH + \
               " --sigpubkeys " + USER_LIST_SIG_PATH

    print_vv(f'calling initPVRA with {init_cmd}')
    # return init_cmd
    # exit(0)
    res = subprocess.run(init_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"initPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    print_vv(res.stdout.decode('utf-8'))


def commandPVRA(state_counter, eCMD, pubkeyCMD):
    # todo get FT
    ft_path = os.path.join(HOST_PATH, "FT.txt")
    ft_sig_path = os.path.join(HOST_PATH, "signedFT.bin")
    cmd_path = os.path.join(HOST_PATH, "eCMD.bin")
    cmd_pubkey_path = os.path.join(HOST_PATH, "pubkeyCMD.bin")
    with open(cmd_path, "wb") as f:
        f.write(eCMD)
    with open(cmd_pubkey_path, "wb") as f:
        f.write(pubkeyCMD)

    cmd = APP_PATH + " --commandPVRA" + \
          " --enclave-path " + SIGNED_ENCLAVE_PATH + \
          " --sealedState " + SEAL_STATE_PATH + \
          " --signedFT " + ft_sig_path + \
          " --FT " + ft_path + \
          " --eCMD " + cmd_path + \
          " --eAESkey " + cmd_pubkey_path + \
          " --cResponse " + CRESPONSE_PATH + \
          " --cRsig " + CRESPONSE_SIG_PATH + \
          " --sealedOut " + SEAL_OUT_PATH
    print_vv(f'calling commandPVRA with {cmd}')
    # return "", ""
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"commandPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    # print_vv(res.stdout)
    print_vv(res.stdout.decode("utf-8"))
    cp = subprocess.run(f"cp {SEAL_OUT_PATH} {SEAL_STATE_PATH}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    assert cp.returncode == 0
    with open(CRESPONSE_PATH, "rb") as f:
        cResponse = f.read()
    with open(CRESPONSE_SIG_PATH, "rb") as f:
        cResponse_sig = f.read()
    return cResponse, cResponse_sig


def auditlogPVRA(state_counter):
    # todo get FT .. why doesn't this need an FT rn?
    audit_cmd = APP_PATH + " --auditlogPVRA" + \
                " --enclave-path " + SIGNED_ENCLAVE_PATH + \
                " --sealedState " + SEAL_STATE_PATH + \
                " --auditlog " + AUDIT_LOG_PATH + \
                " --auditlogsig " + AUDIT_LOG_SIG_PATH + \
                " --sealedOut " + SEAL_OUT_PATH
    print_vv(f'calling auditlogPVRA with {audit_cmd}')
    res = subprocess.run(audit_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"auditlogPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    print_vv(res.stdout.decode("utf-8") )
    cp = subprocess.run(f"cp {SEAL_OUT_PATH} {SEAL_STATE_PATH}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    assert cp.returncode == 0
    with open(AUDIT_LOG_PATH, "rb") as f:
        audit_log = f.read()
    with open(AUDIT_LOG_SIG_PATH, "rb") as f:
        audit_log_sig = f.read()
    return audit_log, audit_log_sig