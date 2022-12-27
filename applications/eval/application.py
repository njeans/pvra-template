import os
import ctypes

import constants

assert os.environ.get("APP_NAME") == "eval"

USER_CMD0 = 0
ADMIN_CMD1 = 1

constants.MERKLE(False)

def get_test_data(admin, users, test_case=None):
    assert test_case == "eval"
    num_users = len(users)
    base_test_data = [
        [({"tid": USER_CMD0, "seq": i}, "success USER_CMD0") for i in range(num_users)]
    ]
    base_admin_data = [
        [None for i in range(num_users)]
    ]
    test_data = base_test_data 
    admin_data = base_admin_data 
    return test_data, admin_data


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


def format_leaf(uidx):
    return bytes(userLeaf(uidx))


def leaf_dic(uidx):
    return {"uidx": uidx}


def leaf_eq(leaf1, leaf2):
    for k in leaf1:
        if k not in leaf2:
            return False
        if leaf1[k] != leaf2[k]:
            return False
    return True


def get_leaf(buff):
    leaf = userLeaf.from_buffer_copy(buff)
    return {"uidx": leaf.uidx}


def print_leaf(buff):
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