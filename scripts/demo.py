import sys
import unittest

from constants import *
import billboard
import admin as admin_lib
import user as user_lib
import application as app


def test(num_users=NUM_USERS, test_case=None):
    num_users = int(num_users)
    demo(num_users, True, test_case=test_case)


def demo(num_users=NUM_USERS, test_=False, test_case=None):
    num_users = int(num_users)
    admin, users = setup(num_users)
    test_data = app.get_test_data(admin, users, test_case=test_case)
    if MERKLE():
        user_data_cmds, admin_cmds, expected_audit = test_data
        num_commands = check_data(user_data_cmds, admin_cmds, expected_audit=expected_audit)
    else:
        user_data_cmds, admin_cmds = test_data
        num_commands = check_data(user_data_cmds, admin_cmds)
    admin_seq = 0
    for cmd_num in range(num_commands):
        for user_num in range(len(user_data_cmds)):
            user = users[user_num]
            if user_data_cmds[user_num][cmd_num] is None:
                continue
            cmd, expected_resp = user_data_cmds[user_num][cmd_num]
            eCMD = user.encrypt_data(cmd)
            resp = app.print_cResponse(user.send_data(eCMD, seq=cmd["seq"]))
            if test_:
                print(f"cResponse user {user_num} cmd {cmd_num} {resp}")
                if expected_resp not in resp:
                    print("\texpected", expected_resp)
                assert expected_resp in resp
        for user_num in range(len(user_data_cmds)):
            if admin_cmds[user_num][cmd_num] is None:
                continue
            cmd, expected_resp = admin_cmds[user_num][cmd_num]
            admin_seq += 1
            eCMD = admin.admin_user.encrypt_data(cmd)
            resp = app.print_cResponse(admin.admin_user.send_data(eCMD, seq=admin_seq))
            if test_:
                print(f"cResponse admin user {user_num} cmd {cmd_num} {resp}")
                if expected_resp not in resp:
                    print("\texpected", expected_resp)
                assert expected_resp in resp
        admin.audit()
    admin.shutdown_server()


def data_omission_demo(num_users=NUM_USERS, modes=None):
    num_users = int(num_users)
    default_mode = INCL_SIG
    default_modes = [OMIT_SIG, OMIT_DATA, INCL_SIG, INCL_DATA]
    if modes is None:
        modes = default_modes
    else:
        modes = modes.split(",")
        assert all([m in default_modes for m in modes])
    user_modes = [modes[i % len(modes)] for i in range(num_users)]

    admin, users = setup(num_users)

    user_data_cmds, omit_index, admin_cmds = app.get_test_data_omission(admin, users)
    num_commands = check_data(user_data_cmds, admin_cmds, omit_index=omit_index)
    for cmd_num in range(num_commands):
        eCMDs = []
        for user_num in range(num_users):
            user = users[user_num]
            mode = default_mode
            if cmd_num in omit_index:
                mode = user_modes[user_num]
            cmd = user_data_cmds[user_num][cmd_num]
            if cmd is None:
                continue
            eCMD = user.encrypt_data(cmd)
            user.send_data(eCMD, mode=mode)
            eCMDs.append(eCMD)
        if cmd_num in omit_index:
            audit_mode = {}
            for i in range(num_users):
                audit_mode[users[i].address] = user_modes[i]
            admin.audit(audit_mode)

            for i in range(num_users):
                users[i].verify_omission(eCMDs[i], user_modes[i])
        else:
            admin.audit(default_mode)
    admin.shutdown_server()


def eval(num_users=NUM_USERS):
    pass  # TODO


def setup(num_users=NUM_USERS):
    num_users = int(num_users)
    assert num_users > 0

    w3 = billboard.setup_w3()
    bb_info = billboard.get_keys(num_users=num_users)

    admin = admin_lib.Admin(w3, bb_info[0])
    admin.start_server()
    contract = admin.contract
    users = [user_lib.User(i, bb_info[i], w3, contract) for i in range(1, num_users+1)]

    for j in range(num_users):
        users[j].verify_bb_info()

    return admin, users


def check_data(user_data_cmds, admin_cmds, expected_audit=None, omit_index=None):
    num_users = len(user_data_cmds)
    assert len(admin_cmds) == len(user_data_cmds)
    num_commands = len(user_data_cmds[0])
    assert num_commands > 0
    for i in range(num_users):
        assert len(admin_cmds[i]) == len(user_data_cmds[i])
        assert num_commands == len(user_data_cmds[i])
    if expected_audit is not None:
        assert len(expected_audit) == len(user_data_cmds)
        for i in range(num_users):
            assert len(expected_audit[i]) == len(user_data_cmds[i])
    if omit_index is not None:
        assert_(max(omit_index) < num_commands)
        assert min(omit_index) >= 0
    return num_commands


def assert_(res, admin=None):
    if not res:
        admin.shutdown_server()
    assert res


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
    else:
        test()