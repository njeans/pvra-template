import os
import ctypes
import datetime

import constants

assert os.environ.get("APP_NAME") == "vsc"

STATUS_UPDATE = 0
STATUS_QUERY = 1

constants.MERKLE(False)


def get_test_data(admin, users):
    num_users = len(users)
    test_data = []
    admin_data = []
    results = ["ACCESS GRANTED", "ACCESS DENIED"]
    test_cases = [[True, True, True, results[1]],
                  [True, True, False, results[1]],
                  [True, False, False, results[0]],
                  [True, False, True, results[1]],
                  [False, True, True, results[1]],
                  [False, True, False, results[1]],
                  [False, False, False, results[0]],
                  [False, False, True, results[1]]]
    for i in range(num_users):
        user_data = [({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][0], "seq": 0}, "success statusUpdate"),
                     ({"tid": STATUS_QUERY, "seq": 1}, "insufficient testing"),
                     ({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][1], "seq": 2}, "success statusUpdate"),
                     ({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][2], "seq": 3}, "success statusUpdate"),
                     ({"tid": STATUS_QUERY, "seq": 4}, test_cases[i % len(test_cases)][3])]
        test_data.append(user_data)
        admin_data.append([None for _ in range(len(user_data))])
    return test_data, admin_data


def get_test_data_omission(admin, users):
    test_data, admin_data = get_test_data(admin, users)
    test_data = [list(zip(*test_data[i]))[0] for i in range(len(test_data))]
    return test_data, [3], admin_data


def format_command(cmd):
    if "test_result" not in cmd:
        cmd["test_result"] = False
    CI = cInputs(cmd["test_result"])
    pc = private_command(cmd["tid"], cmd["seq"], CI)
    res = bytes(pc)
    return res


def print_leaf(buff):
    return ""


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    if b'ACCESS ' in resp.message:
        ret["access"] = resp.access
    return str(ret)


class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_uint32),
                ('message', ctypes.c_char * 100),
                ('access', ctypes.c_bool)]


class cInputs(ctypes.Structure):
    _fields_ = [('test_result', ctypes.c_bool)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('seq', ctypes.c_uint32),
                ('cInputs', cInputs)]

