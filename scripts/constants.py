import os

verbose = 2

# colors = ['\033[93m', '\033[94m', '\033[95m', '\033[96m', '\033[90m', '\033[92m']
# end = '\033[0m'

ERRORc = '\033[0;31m'
ADMINc = '\033[0;35m'
USERc = ['\033[0;32m', '\033[0;34m', '\033[0;33m', '\033[0;36m']
NOCOLOR = '\033[0m'
U32_SIZE = 4
U64_SIZE = 8
HASH_SIZE = 32
PACKED_ADDR_SIZE = 32

OMIT_SIG = "omit_sig"  # uses admin signature to prove omission
OMIT_DATA = "omit_data"  # user uses posted data to prove omission
INCL_SIG = "sig"  # normal optimized case
INCL_DATA = "data"  # admin gets data from bulletin board

PROJECT_ROOT = os.environ.get('PROJECT_ROOT')
IAS_PRIMARY_KEY = os.environ.get("IAS_PRIMARY_KEY")

BILLBOARD_URL = os.environ.get('BILLBOARD_URL', 'http://billboard:8545')
IAS_URL = os.environ.get('IAS_URL', "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report")
NUM_USERS = int(os.environ.get('NUM_USERS', 4))

ADMIN_IP = 'localhost'
ADMIN_PORT = 8081
APP_NAME = os.environ.get("APP_NAME")

if os.environ.get("deployment_location", "") == "DOCKER":
    APP_SRC_PATH = os.path.join(PROJECT_ROOT, "src")
else:
    APP_SRC_PATH = os.path.join(PROJECT_ROOT, "applications", APP_NAME)

APP_PATH = os.path.join(PROJECT_ROOT, "bin", "app")
SIGNED_ENCLAVE_PATH = os.path.join(PROJECT_ROOT, "bin", "enclave.signed.so")
TEST_PATH = os.path.join(PROJECT_ROOT, "test_sgx")

HOST_PATH = os.path.join(TEST_PATH, "host")
SEAL_STATE_PATH = os.path.join(HOST_PATH, "sealedState.bin")
SEAL_STATE0_PATH = os.path.join(HOST_PATH, "sealedState0.bin")
SEAL_OUT_PATH = os.path.join(HOST_PATH, "sealedOut.bin")
QUOTE_FILE_PATH = os.path.join(HOST_PATH, "quote.bin")
USER_LIST_PATH = os.path.join(HOST_PATH, "pubkeys.list")
USER_LIST_SIG_PATH = os.path.join(HOST_PATH, "pubkeys.sig")
AUDIT_LOG_PATH = os.path.join(HOST_PATH, "auditlog.bin")
AUDIT_LOG_SIG_PATH = os.path.join(HOST_PATH, "auditlog.sig")
IAS_REPORT_PATH = os.path.join(HOST_PATH, "ias_report.json")

CRESPONSE_PATH = os.path.join(HOST_PATH, "cResponse.txt")
CRESPONSE_SIG_PATH = os.path.join(HOST_PATH, "cResponse.sig")

CLIENT_PATH = os.path.join(TEST_PATH, "client")

SIGN_KEY_PATH = os.path.join(TEST_PATH, "signingkey.bin")
ENCLAVE_PUBLIC_KEY_PATH = os.path.join(TEST_PATH, "enclave_enc_pubkey.bin")
ENCLAVE_PUBLIC_KEY_SIG_PATH = os.path.join(TEST_PATH, "enclave_enc_pubkey.sig")
CONTRACT_ADDRESS_PATH = os.path.join(TEST_PATH, "contract_address")

BILLBOARD_ACCOUNTS_PATH = os.path.join(PROJECT_ROOT, "accounts", 'accounts.json')
SOLIDITY_PATHS = (os.path.join(PROJECT_ROOT, "solidity"), 'Billboard.sol', [])

ENCLAVE_PUBLIC_KEY_default = ""


def ENCLAVE_PUBLIC_KEY():
    global ENCLAVE_PUBLIC_KEY_default
    if ENCLAVE_PUBLIC_KEY_default == "":
        try:
            print(f"Reading ENCLAVE_PUBLIC_KEY from {ENCLAVE_PUBLIC_KEY_PATH}")
            with open(ENCLAVE_PUBLIC_KEY_PATH, "rb") as f:
                ENCLAVE_PUBLIC_KEY_default = f.read()
        except Exception as e:
            print(f"Warning ENCLAVE_PUBLIC_KEY not set yet {e}")
        if len(ENCLAVE_PUBLIC_KEY_default) == 65:
            ENCLAVE_PUBLIC_KEY_default = ENCLAVE_PUBLIC_KEY_default[1:]
    return ENCLAVE_PUBLIC_KEY_default


MERKLE_default = False


def MERKLE(merkle=None):
    global MERKLE_default
    if merkle is not None:
        MERKLE_default = merkle
    return MERKLE_default
