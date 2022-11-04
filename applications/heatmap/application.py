import os
import random
import ctypes
import datetime

import numpy as np
import matplotlib.pyplot as plt

import constants

assert os.environ.get("APP_NAME") == "heatmap"

ADD_DATA = 0
GET_HM = 1

constants.MERKLE(False)
max_lat = 40.25
max_lng = 116.75
min_lat = 39.5
min_lng = 116.0
heatmap_info_beijing = {
    "map_file": os.path.join(constants.APP_SRC_PATH, "beijing.png"),
    "min_lat": 39.5,
    "max_lat": 40.25,
    "min_long": 116.0,
    "max_long": 116.75,
    "min_x": 12950,
    "max_x": 13025,
    "min_y": 29600,
    "max_y": 29675
}
hm_granularity = 10


def get_test_data(admin, users, num_data=2):
    num_users = len(users)
    assert num_data > 0
    data = random_data(num_users, num_data)
    test_data = []
    admin_data = []

    for i in range(num_users):
        data_for_user = data[i]
        user_data = []
        for j in range(num_data):
            user_data.append(({"tid": ADD_DATA, "input_data": data_for_user[j], "seq": j}, "success addPersonalData"))
        user_data.append(None)
        test_data.append(user_data)
        admin_data.append([None for _ in range(num_data+1)])
    admin_data[num_users-1][num_data] = ({"tid": GET_HM}, "heatmap_")

    return test_data, admin_data


def get_test_data_omission(admin, users):
    test_data, admin_data = get_test_data(admin, users, num_data=1)
    test_data = [list(unzip_none(t))[0] for t in test_data]
    return test_data, [0], admin_data


def format_command(cmd):
    if "input_data" not in cmd:
        cmd["input_data"] = {}
        cmd["input_data"]["lat"] = 0.0
        cmd["input_data"]["lng"] = 0.0
        cmd["input_data"]["startTs"] = 0
        cmd["input_data"]["endTs"] = 0
        cmd["input_data"]["testResult"] = False
    CI = cInputs(cmd["input_data"]["lat"],
                 cmd["input_data"]["lng"],
                 cmd["input_data"]["startTs"],
                 cmd["input_data"]["endTs"],
                 cmd["input_data"]["testResult"])
    pc = private_command(cmd["tid"], cmd["seq"], CI)
    res = bytes(pc)
    return res


def print_cResponse(buff):
    resp = cResponse.from_buffer_copy(buff)
    ret = {"error": resp.error,
           "message": resp.message}
    if b'success getHeatMap' in resp.message:
        ret["heatmap_data"] = save_heatmap(resp.heatmap_data)
    return str(ret)


def save_heatmap(hm):
    max_x = heatmap_info_beijing["max_x"]
    min_x = heatmap_info_beijing["min_x"]
    max_y = heatmap_info_beijing["max_y"]
    min_y = heatmap_info_beijing["min_y"]
    x_range = max_x - min_x+1
    y_range = max_y - min_y+1
    num_labels_x = 3*int((hm_granularity/3))
    num_labels_y = int(num_labels_x/.75)
    # print("num_bins", num_labels_x, num_labels_y)
    width = 9
    height = 12

    heatmap_vals_round = np.zeros((num_labels_x, num_labels_y))
    for i in range(len(hm)):
        x_idx = int(i/hm_granularity)
        y_idx = i % hm_granularity
        x_loc = int(num_labels_x*x_idx/hm_granularity)
        y_loc = int(num_labels_y*y_idx/hm_granularity)
        # print(i,"x_idx",x_idx,"y_idx",y_idx,"xloc:",x_loc,"yloc:",y_loc, "hm[i]", hm[i])
        heatmap_vals_round[x_loc][y_loc] = hm[i]
    # print(heatmap_vals_round)
    hm_info = heatmap_info_beijing
    plt.figure(figsize=(width, height))

    xtic = np.arange(0, num_labels_x, step=1)
    xlab = ['{:4f}'.format(hm_info["min_long"] + (hm_info["max_long"]-hm_info["min_long"])*(val/num_labels_x)) for val in xtic]
    plt.xticks(ticks=xtic, labels=xlab, rotation=-45)

    ytic = np.arange(0, num_labels_y, step=1)
    ylab = ['{:4f}'.format(hm_info["min_lat"] + (hm_info["max_lat"]-hm_info["min_lat"])*(val/num_labels_y)) for val in ytic]
    plt.yticks(ticks=ytic, labels=ylab)

    plt.title("tDrive Heatmap audit_num: ")
    im2 = plt.imshow(heatmap_vals_round.transpose(), origin='lower', cmap='Reds', aspect='equal', extent=(0.0, width, 0.0, height))
    bmap = plt.imread(hm_info["map_file"])
    im = plt.imshow(bmap, extent=(0, width, 0, height), alpha=.3)
    fname = f"heatmap_{hm_granularity}_{datetime.datetime.now()}.png"
    plt.savefig(fname)
    return fname


def random_data(num_users, num_data):
    all_data = []
    for j in range(num_users):
        data = []
        for i in range(num_data):
            lng = min_lng + (j*(max_lng-min_lng)/(num_users))#random.uniform(min_lng, max_lng)
            lat = min_lat + (j*(max_lat-min_lat)/num_users)#random.uniform(min_lat, max_lat)
            data += [
                {
                    "lat": lat,
                    "lng": lng,
                    "startTs": 1583067001+j,
                    "endTs": 1583067601+j,
                    "testResult": True,
                }
            ]
        all_data.append(data)
    return all_data



class cResponse(ctypes.Structure):
    _fields_ = [('error', ctypes.c_uint32),
                ('message', ctypes.c_char * 100),
                ('heatmap_data', ctypes.c_uint32 * (hm_granularity*hm_granularity))]


class cInputs(ctypes.Structure):
    _fields_ = [('lat', ctypes.c_float),
                ('lng', ctypes.c_float),
                ('startTs', ctypes.c_uint64),
                ('endTs', ctypes.c_uint64),
                ('result', ctypes.c_bool)]


class private_command(ctypes.Structure):
    _fields_ = [('tid', ctypes.c_uint32),
                ('seq', ctypes.c_uint32),
                ('cInputs', cInputs)]


def unzip_none(ls):
    for i in range(len(ls)):
        if ls[i] is None:
            ls[i] = [None, None]
    return zip(*ls)

