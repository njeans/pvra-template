import os
import ctypes
import datetime

import constants

assert os.environ.get("APP_NAME") == "vsc"

STATUS_UPDATE = 0
STATUS_QUERY = 1

constants.MERKLE(False)


def get_test_data(admin, users, test_case=None):
    if test_case == "seqno_test":
        return seqno_test(admin, users)
    if test_case == "large_test":
        return large_test(admin, users)
    return functionality_test(admin, users)


def get_test_data_omission(admin, users):
    test_data, admin_data, _ = get_test_data(admin, users)
    test_data = [list(zip(*test_data[i]))[0] for i in range(len(test_data))]
    for t in test_data:
        for x in t:
            del x["seq"]
    return test_data, [3], admin_data


def format_command(cmd):
    if "test_result" not in cmd:
        cmd["test_result"] = False
    CI = cInputs(cmd["test_result"])
    pc = private_command(cmd["tid"], CI)
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
    _fields_ = [('error', ctypes.c_int),
                ('message', ctypes.c_char * 100),
                ('access', ctypes.c_bool)]


class cInputs(ctypes.Structure):
    _fields_ = [('test_result', ctypes.c_bool)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('cInputs', cInputs)]


def functionality_test(admin, users):
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FUNCTIONALITY_TESTS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
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
        user_data = [({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][0], "seq": 1}, "success statusUpdate"),
                     ({"tid": STATUS_QUERY, "seq": 2}, "insufficient testing"),
                     ({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][1], "seq": 3}, "success statusUpdate"),
                     ({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][2], "seq": 4}, "success statusUpdate"),
                     ({"tid": STATUS_QUERY, "seq": 5}, test_cases[i % len(test_cases)][3])]
        test_data.append(user_data)
        admin_data.append([None for _ in range(len(user_data))])
    return test_data, admin_data, None


def large_test(admin, users, num_tests=12):
    assert num_tests % 3 == 0, "num_tests for large_test should be a multiple of 3 to get accurate test cases"
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~LARGE_TESTS: {num_tests}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
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
        user_data = [({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][j%3], "seq": j+1}, "success statusUpdate") for j in range(num_tests)]
        user_data.append(({"tid": STATUS_QUERY, "seq": num_tests+2}, test_cases[i % len(test_cases)][3]))
        test_data.append(user_data)
        admin_data.append([None for _ in range(len(user_data))])
    return test_data, admin_data, None

def seqno_test(admin, users):
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~SEQUENCE_NUM_TESTS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
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
        user_data = [({"tid": STATUS_UPDATE, "test_result": test_cases[i % len(test_cases)][0], "seq": 1}, "success statusUpdate"),
                     ({"tid": STATUS_QUERY, "seq": 3}, "SeqNo failure received [3] != [2] NOT logging")]
        test_data.append(user_data)
        admin_data.append([None for _ in range(len(user_data))])
    return test_data, admin_data, None
