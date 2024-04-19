#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   entry.py
@Time    :   2022/08/11
@Author  :   @Puzzor 
@Version :   1.0
@Contact :   puzzorsj@gmail.com
@Desc    :   None
'''

# here put the import lib

import os
import struct
import hashlib
import pdb
from ppadb.client import Client as AdbClient
import time

cur_path = os.path.dirname(os.path.abspath(__file__))


def compose_config_prop(device, interface_token=""):
    """
    Create config.prop file
    """
    cmd = "service list|grep {}".format(interface_token)
    output = device.shell(cmd)
    output = output.strip().split(" ")
    service_name = output[0]
    service_name = service_name.replace(":", "").split("\t")[1]

    prop_str = """SERVICE_NAME:{}
INTERFACE_TOKEN:{}
SERVICE_FIRST_CALL:0
SERVICE_LAST_CALL:1000
IS_SA:0
""".format(service_name, interface_token)
    if not os.path.exists(os.path.join(cur_path, interface_token)):
        os.mkdir(os.path.join(cur_path, interface_token))
    config_prop_path = os.path.join(cur_path, interface_token, "config.prop")
    with open(config_prop_path, "w", newline="\n") as f:
        f.write(prop_str)


def extract_interface_token_from_data(data, code=0):
    """
    """
    # data+0xC存储了interface token的字符串长度
    # str_length = data[0xC:0x10] # For AOSP
    str_length = data[0x8:0xC]  # For HuaWei HMOS

    str_length = struct.unpack("<I", str_length)
    # print(str_length[0])
    # pdb.set_trace()
    # 根据长度解析interface token
    # interface_token = data[0x10:0x10+str_length[0]*2] # For AOSP
    interface_token = data[0xC:0xC+str_length[0]*2]  # For Huawei HMOS
    token = interface_token.replace(b"\x00", b"").decode("utf-8")
    print("Token: {}".format(token))
    if (len(token)) <= 1:
        print("Token too short, skip")
        return
    payload = data[0x10+str_length[0]*2+2:-2]
    # print("Payload: {}".format(payload))
    # print("Payload len : {}".format(len(payload)))

    # 写入文件夹
    if not os.path.exists(os.path.join(cur_path, token)):
        os.mkdir(os.path.join(cur_path, token))
        os.mkdir(os.path.join(cur_path, token, "in"))

    # 根据data的哈希命名seed
    md = hashlib.md5()
    md.update(payload)
    digest = "{}-{}".format(code, md.hexdigest())
    seed_path = os.path.join(cur_path, token, "in", digest)
    if not os.path.exists(seed_path):
        with open(seed_path, "wb") as f:
            f.write(struct.pack("<I", code)+payload)


def first_stage():
    """
    上传文件，重启，准备工作
    """
    # 获取所有devices
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()

    for device in devices:
        cmd = "adb -s {} root".format(device.serial)
        # print(cmd)
        os.system(cmd)
        cmd = "adb -s {} remount".format(device.serial)
        # print(cmd)
        os.system(cmd)

        if not os.path.exists(os.path.join(cur_path, "libbinder.so.bak")):
            cmd = "adb -s {} pull {} {}".format(
                device.serial, "/system/lib64/libbinder.so", os.path.join(cur_path, "libbinder.so.bak"))
            # print(cmd)
            os.system(cmd)

        # 拷贝libbinder.so到目标设备
        # 这一步有时候会出现bug，push不上去，不知道是哪里的问题
        # 遇到这种情况，手工push一下， 然后reboot
        cmd = "adb -s {} push {} {}".format(device.serial, os.path.join(
            cur_path, "libbinder.so"), "/system/lib64/libbinder.so")
        # print(cmd)
        os.system(cmd)

        # 重启设备
        cmd = "adb -s {} reboot ".format(device.serial)
        # print(cmd)
        os.system(cmd)

    # sleep 30秒等重启
    print("Waiting for device to reboot")
    time.sleep(60)

    # 获取所有devices
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        cmd = "adb -s {} root".format(device.serial)
        # print(cmd)
        os.system(cmd)
        cmd = "setenforce 0"
        device.shell(cmd)

    # sleep 60秒等待收集数据
    print("Waiting for seed collection")
    time.sleep(60)


def second_stage():
    """
    收集并处理数据
    """
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        local_dat_path = os.path.join(cur_path, device.serial+".dat")
        device.pull("/data/local/tmp/afile.dat", local_dat_path)
        print(local_dat_path)

        with open(local_dat_path, "rb") as f:
            content = f.read()
            datas = content.split(b"code:")
            for data in datas:
                code_end_idx = data.find(b"\n")
                code = data[:code_end_idx]
                data = data[code_end_idx+1:]
                if len(data) > 0x10:
                    print("Code: {}".format(code.strip().decode("utf-8")))
                    # print("Data: {}".format(data))

                    try:
                        extract_interface_token_from_data(
                            data, int(code.strip()))
                    except Exception as e:
                        print(e)

        device.shell("rm /data/local/tmp/afile.dat")

        os.unlink(local_dat_path)

    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    device = devices[0]
    for dir in os.listdir(cur_path):
        # 认为所有的目录应该都是interface token，所以不要手动放额外目录文件
        if os.path.isdir(dir):
            # 构造config.prop
            try:
                compose_config_prop(device, dir)
            except Exception as e:
                print(e)
                # 有些interface token 不在service list 里面，可能会抛出异常


def restore_libbinder():
    """
    """
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        cmd = "adb -s {} root".format(device.serial)
        # print(cmd)
        os.system(cmd)
        cmd = "adb -s {} remount".format(device.serial)
        # print(cmd)
        os.system(cmd)

        cmd = "adb -s {} push {} {}".format(device.serial, os.path.join(
            cur_path, "libbinder.so.bak"), "/system/lib64/libbinder.so")
        # print(cmd)
        os.system(cmd)
        cmd = "adb -s {} shell setenforce 1".format(device.serial)
        # print(cmd)
        os.system(cmd)

        cmd = "adb -s {} shell rm /data/local/tmp/afile.dat".format(
            device.serial)
        # print(cmd)
        os.system(cmd)

        cmd = "adb -s {} settings put secure hw_suw_frp_state 0".format(
            device.serial)
        # print(cmd)
        device.shell(cmd)

        cmd = "adb -s {} pm disable com.huawei.hwstartupguide".format(
            device.serial)
        # print(cmd)
        device.shell(cmd)

        cmd = "adb -s {} reboot".format(device.serial)
        # print(cmd)
        os.system(cmd)


first_stage()
while True:
    second_stage()
    time.sleep(120)
# call this stand alone to restore
# restore_libbinder()
