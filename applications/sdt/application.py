import os
import ctypes
import time 

import constants
from utils import sha256

assert os.environ.get("APP_NAME") == "sdt"
SECRET_DATA_SIZE = 64
KEY_SIZE = 64
HASH_SIZE = 32

ADD_DATA = 0
GET_DATA = 2
START_RET = 3
COMPLETE_RET = 4
CANCEL_RET = 1
WAIT_TIME = 30
RESET_TIME = 120

constants.MERKLE(True)


def get_test_data(admin, users, test_case=None):
    num_users = len(users)
    assert num_users <= 6
    assert num_users >= 2
    secret_data = lambda i: bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8")
    base_test_data = [
        [({"tid": ADD_DATA, "input_data": secret_data(0), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(0))),
        ],
        [({"tid": ADD_DATA, "input_data": secret_data(1), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         None,
         ],
        [None,
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(1))),
        ],
        [({"tid": ADD_DATA, "input_data": secret_data(2), "seq": 1}, "success addPersonalData"),
         None,
         ({"tid": CANCEL_RET, "seq": 2}, "success cancelRetrieve"),
         None,
         ({"tid": GET_DATA, "seq": 3}, str(secret_data(2))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(3), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(3))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(4), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(4))),
         ]
    ]
    #user 0 data stolen by user 1
    #user 2 admin didn't wait
    #user 3 canceled in time
    #user 4 recover key changed
    #user 5 limit reached and then started after reset time
    get_pubkey = lambda i: users[i].public_key
    get_pubkey_hash = lambda i: sha256(users[i].public_key)
    base_admin_data = [
        [None,
         ({"tid": START_RET, "user_pubkey": 0, "recover_key_hash": 2}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": 0, "recover_key": 2}, "retrieval wait period not over"),#todo change to retrieval not started
         None
        ],
        [None,
         ({"tid": START_RET, "user_pubkey": 1, "recover_key_hash": 2}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": 1, "recover_key": 2}, "success completeRetrieve"),
         None
        ],
        [None, None, None, None, None],
        [None,
         ({"tid": START_RET, "user_pubkey": 3, "recover_key_hash": 2}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": 3, "recover_key": 2}, "retrieval not started"),
         None
        ],
        [None,
         ({"tid": START_RET, "user_pubkey": 4, "recover_key_hash": 3}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": 4, "recover_key": 2}, "recover key does not match recover_key_hash"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": 5, "recover_key_hash": 2}, "retrieve_count limit reached"),
         None,
         None,
         ({"tid": START_RET, "user_pubkey": 5, "recover_key_hash": 2}, "success startRetrieve")
        ]
    ]
    base_expected_audit = [
        [leaf_dic(0, 0, False, 0), leaf_dic(1, 100, True, 0), leaf_dic(1, 100, True, 0), leaf_dic(1, 100, True, 0), leaf_dic(1, 100, True, 0)],
        [leaf_dic(0, 0, False, 1), leaf_dic(1, 100, True, 1), leaf_dic(1, 100, True, 1), None, None],
        [None, None, None, None, None],
        [leaf_dic(0, 0, False, 3), leaf_dic(1, 100, True, 3), leaf_dic(1, 0, False, 3), leaf_dic(1, 0, False, 3), leaf_dic(1, 0, False, 3)],
        [leaf_dic(0, 0, False, 4), leaf_dic(1, 100, True, 4), leaf_dic(1, 100, True, 4), leaf_dic(1, 100, True, 4), leaf_dic(1, 100, True, 4)],
        [leaf_dic(0, 0, False, 5), leaf_dic(0, 0, False, 5), leaf_dic(0, 0, False, 5), leaf_dic(0, 0, False, 5), leaf_dic(1, 100, True, 5)]
    ]
    def wait_period():
        print(f"sleep for {WAIT_TIME} seconds to ensure wait time complete")
        time.sleep(WAIT_TIME)
    def reset_period():
        print(f"sleep for {RESET_TIME} seconds to ensure reset time complete")
        time.sleep(RESET_TIME)

    base_other_functions = [
        [None, None, None, None, None],
        [None, None, None, wait_period, None],
        [None, None, None, None, None],
        [None, None, None, None,  None],
        [None, None, None, None, None],
        [None, None, None, None, reset_period],
    ]
    test_data = [base_test_data[i] for i in range(num_users)]
    admin_data = [base_admin_data[i] for i in range(num_users)]
    for i in range(len(admin_data)):
        if admin_data[i] is None:
            continue
        for j in range(len(admin_data[i])):
            if admin_data[i][j] is None:
                continue
            cmd = admin_data[i][j][0]
            if "user_pubkey" in cmd:
                admin_data[i][j][0]["user_pubkey"] = get_pubkey(cmd["user_pubkey"])
            if "recover_key" in cmd:
                admin_data[i][j][0]["recover_key"] = get_pubkey(cmd["recover_key"])
            if "recover_key_hash" in cmd:
                admin_data[i][j][0]["recover_key_hash"] = get_pubkey_hash(cmd["recover_key_hash"])
    expected_audit = [base_expected_audit[i] for i in range(num_users)]
    other_functions = [base_other_functions[i] for i in range(num_users)]
    return test_data, admin_data, expected_audit, other_functions


def get_test_data_omission(admin, users):
    num_users = len(users)
    #let the sequence number be handled automatically since omitting data
    #will cause issues
    test_data = [[{"tid": ADD_DATA, "input_data": bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8")},
                  None,
                  {"tid": CANCEL_RET},
                  None,
                  {"tid": GET_DATA}] for i in range(num_users)]
    admin_data = [[None,
                   {"tid": START_RET, "user_pubkey": users[i].public_key, "recover_key_hash": sha256(admin.public_key)},
                   None,
                   {"tid": COMPLETE_RET, "user_pubkey": users[i].public_key, "recover_key": admin.public_key},
                   {"tid": GET_DATA, "user_pubkey": admin.public_key}] for i in range(num_users)]
    return test_data, [2], admin_data

#[admin.py] encrypting user data {'tid': 4
def format_command(cmd):
    if "input_data" not in cmd:
        cmd["input_data"] = b'-' * SECRET_DATA_SIZE
    if "recover_key_hash" not in cmd:
        cmd["recover_key_hash"] = b'-' * HASH_SIZE
    if "recover_key" not in cmd:
        cmd["recover_key"] = b'-' * KEY_SIZE
    if "user_pubkey" not in cmd:
        cmd["user_pubkey"] = b'-' * KEY_SIZE
    data = U8ArrData.from_buffer_copy(cmd["input_data"])
    print(cmd)
    rkh = U8ArrHash.from_buffer_copy(cmd["recover_key_hash"])
    rk = U8ArrKey.from_buffer_copy(cmd["recover_key"])
    pk = U8ArrKey.from_buffer_copy(cmd["user_pubkey"])
    CI = cInputs(data, rkh, rk, pk)
    pc = private_command(cmd["tid"], CI)
    res = bytes(pc)
    return res


def format_leaf(retrieve_count, retrieve_time, started_retrieve, uidx):
    return bytes(userLeaf(retrieve_count, retrieve_time, started_retrieve, uidx))


def leaf_dic(retrieve_count, retrieve_time, started_retrieve, uidx):
    return {"retrieve_count": retrieve_count,
            "retrieve_time": retrieve_time,#todo remove
            "started_retrieve": started_retrieve,
            "uidx": uidx}


def leaf_eq(leaf1, leaf2):
    for k in leaf1:
        if k not in leaf2:
            return False
        if k == "retrieve_time":
            if (str(leaf1[k]) == "0" or str(leaf2[k]) == "0") and str(leaf1[k]) != str(leaf2[k]):
                return False
        elif leaf1[k] != leaf2[k]:
            return False
    return True


def get_leaf(buff):
    leaf = userLeaf.from_buffer_copy(buff)
    return {"retrieve_count": leaf.retrieve_count,
                "retrieve_time": leaf.retrieve_time,
                "started_retrieve": leaf.started_retrieve,
                "uidx": leaf.uidx}


def print_leaf(buff):
    return str(get_leaf(buff))


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    if b'success getPersonalData' in resp.message:
        ret["output_data"] = bytes(resp.output_data)
    return str(ret)


U8ArrData = ctypes.c_uint8 * SECRET_DATA_SIZE
U8ArrKey = ctypes.c_uint8 * KEY_SIZE
U8ArrHash = ctypes.c_uint8 * HASH_SIZE

class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_int),
                ('message', ctypes.c_char * 100),
                ('output_data', U8ArrData)]


class cInputs(ctypes.Structure):
    _fields_ = [('input_data', U8ArrData),
                ('recover_key_hash', U8ArrHash),
                ('recover_key', U8ArrKey),
                ('user_pubkey', U8ArrKey)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('cInputs', cInputs)]

class userLeaf(ctypes.Structure):
    _fields_ = [('retrieve_count', ctypes.c_uint32),
                ('retrieve_time', ctypes.c_uint64),
                ('started_retrieve', ctypes.c_bool),
                ('uidx', ctypes.c_uint32)]