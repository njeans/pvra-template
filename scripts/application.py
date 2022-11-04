import os
import ctypes

import constants

assert os.environ.get("APP_NAME") == "sdt"
SECRET_DATA_SIZE = 64
KEY_SIZE = 64

ADD_DATA = 0
GET_DATA = 2
START_RET = 3
COMPLETE_RET = 4
CANCEL_RET = 1

constants.MERKLE(True)


def get_test_data(admin, users):
    num_users = len(users)
    assert num_users <= 5
    secret_data = lambda i: bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8")
    base_test_data = [
        [({"tid": ADD_DATA, "input_data": secret_data(0), "seq": 0}, "success addPersonalData"),
         None,
         None,
         None,
         None,
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(1), "seq": 0}, "success addPersonalData"),
         None,
         ({"tid": CANCEL_RET, "seq": 1}, "success cancelRetrieve"),
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(1))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(2), "seq": 0}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2}, str(secret_data(2))),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data(2), "seq": 0}, "success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 1}, str(secret_data(3))),
         ],
        [None,
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 1}, str(secret_data(0))),
         ]
    ]
    #user 0 data stolen by user 4
    #user 1 cancel in time
    #user 2 limit reached
    #user 3 admin didn't wait
    base_admin_data = [
        [None,
         ({"tid": START_RET, "user_pubkey": users[0].public_key}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "user_pubkey": users[0].public_key, "recover_key": users[4].public_key}, "success completeRetrieve"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[1].public_key}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": users[4].public_key, "user_pubkey": users[1].public_key}, "retrieval not started"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[2].public_key}, "success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": users[4].public_key, "user_pubkey": users[2].public_key}, "retrieval wait period not over"),
         None
         ],
        [None,
         ({"tid": START_RET, "user_pubkey": users[3].public_key}, "retrieve_count limit reached"),
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
        [format_leaf(0, 0, False, 3), format_leaf(1, 73, True, 3), format_leaf(1, 73, True, 3), format_leaf(1, 73, True, 3), format_leaf(1, 73, True, 3)],
        [None, None, None, None, None]
    ]
    test_data = [base_test_data[i] for i in range(num_users)]
    admin_data = [base_admin_data[i] for i in range(num_users)]
    expected_audit = [base_expected_audit[i] for i in range(num_users)]
    return test_data, admin_data, expected_audit


def get_test_data_omission(admin, users):
    num_users = len(users)
    test_data = [[{"tid": ADD_DATA, "input_data": bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8"), "seq": 0},
                  None,
                  {"tid": CANCEL_RET, "seq": 1},
                  None,
                  {"tid": GET_DATA, "seq": 2}] for i in range(num_users)]
    admin_data = [[None,
                   {"tid": START_RET, "user_pubkey": users[i].public_key},
                   None,
                   {"tid": COMPLETE_RET, "user_pubkey": users[i].public_key, "recover_key": admin.public_key},
                   {"tid": GET_DATA, "user_pubkey": admin.public_key}] for i in range(num_users)]
    return test_data, [2], admin_data

#[admin.py] encrypting user data {'tid': 4
def format_command(cmd):
    if "input_data" not in cmd:
        cmd["input_data"] = b'-' * SECRET_DATA_SIZE
    if "recover_key" not in cmd:
        cmd["recover_key"] = b'-' * KEY_SIZE
    if "user_pubkey" not in cmd:
        cmd["user_pubkey"] = b'-' * KEY_SIZE
    CI = cInputs(cmd["input_data"], cmd["recover_key"][:64], cmd["user_pubkey"])
    assert len(cmd["recover_key"]) == KEY_SIZE
    CI.recover_key = cmd["recover_key"]
    pc = private_command(cmd["tid"], cmd["seq"], CI)
    res = bytes(pc)
    print("format_command")
    print("res", res.hex())
    print("CI", bytes(CI).hex())
    print("cmd[recover_key]", cmd["recover_key"].hex(), len(cmd["recover_key"]))
    print("CI.recover_key", CI.recover_key.hex(), len(CI.recover_key), KEY_SIZE, CI.recover_key)
    print("pc.cInputs.recover_key", pc.cInputs.recover_key.hex())
    return res


def format_leaf(retrieve_count, retrieve_time, started_retrieve, uidx):
    return bytes(userLeaf(retrieve_count, retrieve_time, started_retrieve, uidx))


def print_leaf(buff):
    leaf = userLeaf.from_buffer_copy(buff)
    return str({"retrieve_count": leaf.retrieve_count,
                "retrieve_time": leaf.retrieve_time,
                "started_retrieve": leaf.started_retrieve,
                "uidx": leaf.uidx})


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    if b'success getPersonalData' in resp.message:
        ret["output_data"] = resp.output_data
    return str(ret)


def strip(buff):
    if b'\x00' in buff:
        return buff[:buff.index(b'\x00')]
    return buff


class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_uint32),
                ('message', ctypes.c_char * 100),
                ('output_data', ctypes.c_char * SECRET_DATA_SIZE)]


class cInputs(ctypes.Structure):
    _fields_ = [('input_data', ctypes.c_char * SECRET_DATA_SIZE),
                ('recover_key', ctypes.c_char * KEY_SIZE),
                ('user_pubkey', ctypes.c_char * KEY_SIZE)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('seq', ctypes.c_uint32),
                ('cInputs', cInputs)]

class userLeaf(ctypes.Structure):
    _fields_ = [('retrieve_count', ctypes.c_uint32),
                ('retrieve_time', ctypes.c_uint64),
                ('started_retrieve', ctypes.c_bool),
                ('uidx', ctypes.c_uint32)]