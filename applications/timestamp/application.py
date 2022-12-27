import os
import sys
import ctypes

import constants

assert os.environ.get("APP_NAME") == "timestamp"

GET_TS = 0

def get_test_data(admin, users, test_case=None):
    num_users = len(users)
    base_test_data = [
        [({"tid": GET_TS, "seq": 1}, "success getTS"),
         None
         ],
        [None,
         ({"tid": GET_TS,  "seq": 1}, "success getTS"),
         ]
    ]
    base_admin_data = [
        [None, None],
        [None, None],
    ]
    test_data = [base_test_data[i % 2] for i in range(num_users)]
    admin_data = [base_admin_data[i % 2] for i in range(num_users)]
    return test_data, admin_data


def get_test_data_omission(admin, users):
    test_data, admin_data, _ = get_test_data(admin, users)
    return test_data, [2], admin_data


def format_command(cmd):
    # CI = cInputs()
    # pc = private_command(cmd["tid"], CI)
    pc = private_command(cmd["tid"])
    res = bytes(pc)
    return res


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    return str(ret)


class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_uint32),
                ('message', ctypes.c_char * 100)]


class cInputs(ctypes.Structure):
    _fields_ = []


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                # ('cInputs', cInputs)
                ]


class userLeaf(ctypes.Structure):
    _fields_ = [('uidx', ctypes.c_uint32)]


if __name__ == '__main__':
    if len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])