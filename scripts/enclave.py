import ctypes
import sys
import subprocess

from constants import *


def print_vv(*args, c=""):
    if verbose >= 2:
        print(c+"[enclave.py]", *args)
        print(NOCOLOR, end="")

def print_v(*args, c=""):
    if verbose >= 1:
        print(c+"[enclave.py]", *args)
        print(NOCOLOR, end="")

def print_(*args, c=""):
    print(c+"[enclave.py]", *args)
    print(NOCOLOR, end="")


def initPvra(num_users):
    num_users = str(num_users)
    init_cmd = APP_PATH + " --initPVRA" + \
                " --enclave-path " + SIGNED_ENCLAVE_PATH + \
               " --sealedState " + SEAL_STATE_PATH + \
               " --quotefile " + QUOTE_FILE_PATH + \
               " --signature " + ENCLAVE_PUBLIC_KEY_SIG_PATH + \
               " --numusers " + num_users + \
               " --userpubkeys " + USER_LIST_PATH + \
               " --sigpubkeys " + USER_LIST_SIG_PATH

    print_vv(f'calling initPVRA with {init_cmd}')
    res = subprocess.run(init_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"initPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    print_v(res.stdout.decode('utf-8'))


def commandPVRA(state_counter, eCMD, pubkeyCMD, seq):
    # todo get FT
    ft_path = os.path.join(HOST_PATH, "FT.txt")
    ft_sig_path = os.path.join(HOST_PATH, "signedFT.bin")
    cmd_path = os.path.join(HOST_PATH, "eCMD.bin")
    seq_buff = bytes(ctypes.c_uint64(seq))
    with open(cmd_path, "wb") as f:
        f.write(seq_buff+pubkeyCMD+eCMD)

    cmd = APP_PATH + " --commandPVRA" + \
          " --enclave-path " + SIGNED_ENCLAVE_PATH + \
          " --sealedState " + SEAL_STATE_PATH + \
          " --signedFT " + ft_sig_path + \
          " --FT " + ft_path + \
          " --eCMD " + cmd_path + \
          " --cResponse " + CRESPONSE_PATH + \
          " --cRsig " + CRESPONSE_SIG_PATH + \
          " --sealedOut " + SEAL_OUT_PATH
    print_vv(f'calling commandPVRA  state_counter {state_counter} with {cmd}')
    # return "", ""
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"commandPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    # print_vv(res.stdout)
    log = res.stdout.decode("utf-8")
    print_v(log)
    if "SeqNo failure" not in log: #todo find a better way
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
    print_vv(f'calling auditlogPVRA state_counter {state_counter} with {audit_cmd}')
    res = subprocess.run(audit_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if res.returncode != 0:
        print_(f"auditlogPVRA failed with code {res.returncode}\n{res.stdout.decode('utf-8')}{res.stderr.decode('utf-8')}", c=ERRORc)
        exit(res.returncode)
    print_v(res.stdout.decode("utf-8") )
    cp = subprocess.run(f"cp {SEAL_OUT_PATH} {SEAL_STATE_PATH}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    assert cp.returncode == 0
    with open(AUDIT_LOG_PATH, "rb") as f:
        audit_log = f.read()
    with open(AUDIT_LOG_SIG_PATH, "rb") as f:
        audit_log_sig = f.read()
    return audit_log, audit_log_sig

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