import os
import constants

assert os.environ.get("APP_NAME") == "sdt"
SECRET_DATA_SIZE = 64
RECOVER_KEY_SIZE = 64

ADD_DATA = 0
GET_DATA = 2
START_RET = 3
COMPLETE_RET = 4
CANCEL_RET = 1

constants.MERKLE(True)


def get_test_data(admin, users):
    num_users = len(users)
    assert num_users >= 4
    test_data = [[] for _ in range(num_users)]
    admin_data = [[] for _ in range(num_users)]
    expected_audit = [[] for _ in range(num_users)]
    user_seq = [0 for _ in range(num_users)]
    user_seq[3] = 1
    secret_data = [bytes(chr(ord("N")+i) * SECRET_DATA_SIZE, "utf-8") for i in range(num_users)]
    test_data = [
        [({"tid": ADD_DATA, "input_data": secret_data[0], "seq": 0, "uidx": 0}, b"success addPersonalData"),
         None,
         None,
         None,
         None,
         ],
        [({"tid": ADD_DATA, "input_data": secret_data[1], "seq": 0, "uidx": 1}, b"success addPersonalData"),
         None,
         ({"tid": CANCEL_RET, "seq": 1, "uidx": 1}, b"success cancelRetrieve"),
         None,
         ({"tid": GET_DATA, "seq": 2, "uidx": 1}, secret_data[1]),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data[2], "seq": 0, "uidx": 2}, b"success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 2, "uidx": 2}, secret_data[2]),
         ],
        [({"tid": ADD_DATA, "input_data": secret_data[3], "seq": 0, "uidx": 3}, b"success addPersonalData"),
         None,
         None,
         None,
         ({"tid": GET_DATA, "seq": 1, "uidx": 3}, secret_data[3]),
         ]
    ]
    #user 0 data stolen
    #user 1 cancel in time
    #user 2 limit reached
    #user 3 admin didn't wait
    admin_data = [
        [None,
         ({"tid": START_RET, "uidx": 0}, b"success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": admin.admin_user.public_key, "uidx": 0}, b"success completeRetrieve"),
         ({"tid": GET_DATA, "seq": 1, "uidx": 0}, secret_data[0])
         ],
        [None,
         ({"tid": START_RET, "uidx": 1}, b"success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": admin.admin_user.public_key, "uidx": 1}, b"retrieval not started"),
         None
         ],
        [None,
         ({"tid": START_RET, "uidx": 2}, b"success startRetrieve"),
         None,
         ({"tid": COMPLETE_RET, "recover_key": admin.admin_user.public_key, "uidx": 2}, b"retrieval wait period not over"),
         None
         ],
        [None,
         ({"tid": START_RET, "uidx": 3}, b"retrieve_count limit reached"),
         None,
         None,
         None
         ]
    ]
    expected_audit = [
        [format_leaf(0, 0, False), format_leaf(1, 70, True), format_leaf(1, 70, True), format_leaf(1, 0, False), format_leaf(1, 0, False)],
        [format_leaf(0, 0, False), format_leaf(1, 71, True), format_leaf(1, 0, False), format_leaf(1, 0, False), format_leaf(1, 0, False)],
        [format_leaf(0, 0, False), format_leaf(1, 72, True), format_leaf(1, 72, True), format_leaf(1, 72, True), format_leaf(1, 72, True)],
        [format_leaf(0, 0, False), format_leaf(1, 73, True), format_leaf(1, 73, True), format_leaf(1, 73, True), format_leaf(1, 73, True)],
    ]
    return test_data, admin_data, expected_audit


def get_test_data_omission(admin, users):
    num_users = len(users)
    test_data = [[{"tid": ADD_DATA, "input_data": chr(ord("N") + i) * SECRET_DATA_SIZE, "seq": 0},
                  None,
                  {"tid": CANCEL_RET, "seq": 1},
                  None,
                  {"tid": GET_DATA, "uid": users[i].public_key}] for i in range(num_users)]
    admin_data = [[None,
                   {"tid": START_RET, "uid": users[i].public_key},
                   None,
                   {"tid": COMPLETE_RET, "uid": users[i].public_key, "recover_key": admin.public_key},
                   {"tid": GET_DATA, "uid": admin.public_key}] for i in range(num_users)]
    return test_data, [2], admin_data


def format_command(cmd):
    res = cmd["tid"].to_bytes(constants.U32_SIZE, "little")
    res += (cmd["uidx"]).to_bytes(constants.U32_SIZE, "little")
    if "input_data" in cmd:
        res += cmd["input_data"]
    else:
        res += b'-' * SECRET_DATA_SIZE
    if "recover_key" in cmd:
        res += cmd["recover_key"]
    else:
        res += b'-' * RECOVER_KEY_SIZE
    res += cmd["seq"].to_bytes(constants.U32_SIZE, "little")
    return res


def format_leaf(retrieve_count, retrieve_time, started_retrieve):
    return retrieve_count.to_bytes(constants.U32_SIZE, "big") + retrieve_time.to_bytes(constants.U64_SIZE, "big") + bytes([int(started_retrieve)])


def print_leaf(buff):
    # print("uidx",len(buff[-4:]),buff[-4:].hex(),int.from_bytes(buff[-4:], "big"),int.from_bytes(buff[-4:], "little"))
    return str({"retrieve_count": int.from_bytes(buff[:4], "little"),
                "retrieve_time": int.from_bytes(buff[4:12], "little"),
                "started_retrieve": False if buff[13] == 0 else True,
                "uidx": int.from_bytes(buff[-4:], "little"),
                })


def print_cResponse(buff):
    return str({"error": int.from_bytes(buff[:4], "little"),
                "message": strip(buff[4:104]).decode("utf-8"),
                "output_data": strip(buff[104:]).decode("utf-8"),
                })

def strip(buff):
    if b'\x00' in buff:
        return buff[:buff.index(b'\x00')]
    return buff