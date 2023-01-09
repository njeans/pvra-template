import os
import ctypes

import constants

assert os.environ.get("APP_NAME") == "template"

USER_CMD0 = 0
ADMIN_CMD1 = 1

constants.MERKLE(True)  # todo remove no MERKLE

def get_test_data(admin, users, test_case=None):
    num_users = len(users)
    base_test_data = [
        [({"tid": USER_CMD0, "seq": 1}, "success USER_CMD0"),
         None
         ],
        [None,
         ({"tid": USER_CMD0,  "seq": 1}, "success USER_CMD0"),
         ]
    ]
    base_admin_data = [
        [None,
         ({"tid": ADMIN_CMD1, "admin_uidx": 0}, "success ADMIN_CMD1"),
         ],
        [None,
         ({"tid": ADMIN_CMD1, "admin_uidx": 1}, "success ADMIN_CMD1"),
         ]
    ]
    base_expected_audit = [
        [format_leaf(0), format_leaf(0)],  # todo remove no MERKLE
        [format_leaf(1), format_leaf(1)],  # todo remove no MERKLE
    ]
    base_other_functions = lambda i: [lambda : print(f"Ran function before user {i} command 0"), 
        lambda : print(f"Ran function before user {i} command 1")]
    
    test_data = [base_test_data[i % 2] for i in range(num_users)]
    admin_data = [base_admin_data[i % 2] for i in range(num_users)]
    expected_audit = [# todo remove no MERKLE
        base_expected_audit[i % 2] for i in range(num_users)
    ]
    other_functions = [base_other_functions(i % 2) for i in range(num_users)]

    return test_data, admin_data, expected_audit, other_functions  # todo remove no MERKLE
    # return test_data, admin_data, other_functions  # todo *uncomment* MERKLE


def get_test_data_omission(admin, users):
    test_data, admin_data, _ = get_test_data(admin, users)
    return test_data, [2], admin_data


def format_command(cmd):
    if "admin_uidx" not in cmd:
        cmd["admin_uidx"] = 0
    CI = cInputs(cmd["admin_uidx"])
    pc = private_command(cmd["tid"], CI)
    res = bytes(pc)
    return res


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    return str(ret)


def format_leaf(uidx):  # todo remove no MERKLE
    return bytes(userLeaf(uidx))


def leaf_dic(uidx):  # todo remove no MERKLE
    return {"uidx": uidx}


def leaf_eq(leaf1, leaf2):  # todo remove no MERKLE
    for k in leaf1:
        if k not in leaf2:
            return False
        if leaf1[k] != leaf2[k]:
            return False
    return True


def get_leaf(buff):  # todo remove no MERKLE
    leaf = userLeaf.from_buffer_copy(buff)
    return {"uidx": leaf.uidx}


def print_leaf(buff):  # todo remove no MERKLE
    return str(get_leaf(buff))


class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_uint32),
                ('message', ctypes.c_char * 100)]


class cInputs(ctypes.Structure):
    _fields_ = [('admin_uidx', ctypes.c_uint32)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('cInputs', cInputs)]


class userLeaf(ctypes.Structure):
    _fields_ = [('uidx', ctypes.c_uint32)]