import os
import ctypes

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

constants.MERKLE(True)


def get_test_data(admin, users, test_case=None):
    num_users = len(users)
    assert num_users <= 5
    secret_data = lambda i: bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8")
    base_test_data = [
        [({"tid": ADD_DATA, "input_data": secret_data(0), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         None,
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(1), "seq": 1}, "success addPersonalData"),
         None,
         ({"tid": CANCEL_RET, "seq": 2}, "success cancelRetrieve"),
         None,
         ({"tid": GET_DATA, "seq": 3}, str(secret_data(1))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(2), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(2))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(3), "seq": 1}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(3))),
         ],
        [None,
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(0))),
         ]
    ]
    #user 0 data stolen by user 4
    #user 1 cancel in time
    #user 2 limit reached
    #user 3 admin didn't wait
    base_admin_data = [
        [None,
         ({"tid": START_RET, "user_pubkey": users[0].public_key, "recover_key_hash": sha256(users[4].public_key)}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": users[0].public_key, "recover_key": users[4].public_key}, "success completeRetrieve"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[1].public_key, "recover_key_hash": sha256(users[4].public_key)}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": users[4].public_key, "user_pubkey": users[1].public_key}, "retrieval not started"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[2].public_key, "recover_key_hash": sha256(users[0].public_key)}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": users[4].public_key, "user_pubkey": users[2].public_key}, "recover key does not match recover_key_hash"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[3].public_key, "recover_key_hash": sha256(users[4].public_key)}, "retrieve_count limit reached"),
         None,
         None,
         None
         ],
        [None, None, None, None, None]
    ]
    base_expected_audit = [
        [format_leaf(0, 0, False, 0), format_leaf(1, 70, True, 0), format_leaf(1, 70, True, 0), format_leaf(1, 0, False, 0), format_leaf(1, 0, False, 0)],
        [format_leaf(0, 0, False, 1), format_leaf(1, 71, True, 1), format_leaf(1, 0, False, 1), format_leaf(1, 0, False, 1), format_leaf(1, 0, False, 1)],
        [format_leaf(0, 0, False, 2), format_leaf(1, 72, True, 2), format_leaf(1, 72, True, 2), format_leaf(1, 72, True, 2), format_leaf(1, 72, True, 2)],
        [format_leaf(0, 0, False, 3), format_leaf(0, 0, False, 3), format_leaf(0, 0, False, 3), format_leaf(0, 0, False, 3), format_leaf(0, 0, False, 3)],
        [None, None, None, None, None]
    ]
    test_data = [base_test_data[i] for i in range(num_users)]
    admin_data = [base_admin_data[i] for i in range(num_users)]
    expected_audit = [base_expected_audit[i] for i in range(num_users)]
    return test_data, admin_data, expected_audit


def get_test_data_omission(admin, users):
    num_users = len(users)
    test_data = [[{"tid": ADD_DATA, "input_data": bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8"), "seq": 1},
                  None,
                  {"tid": CANCEL_RET, "seq": 2},
                  None,
                  {"tid": GET_DATA, "seq": 3}] for i in range(num_users)]
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
    rkh = U8ArrHash.from_buffer_copy(cmd["recover_key_hash"])
    rk = U8ArrKey.from_buffer_copy(cmd["recover_key"])
    pk = U8ArrKey.from_buffer_copy(cmd["user_pubkey"])
    CI = cInputs(data, rkh, rk, pk)
    pc = private_command(cmd["tid"], CI)
    res = bytes(pc)
    # assert len(CI.recover_key) == KEY_SIZE
    return res


def format_leaf(retrieve_count, retrieve_time, started_retrieve, uidx):
    return bytes(userLeaf(retrieve_count, retrieve_time, started_retrieve, uidx))


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
    _fields_ = [('error', ctypes.c_uint32),
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