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
from ppadb.client import Client as AdbClient
import hashlib
import pdb
import shutil
import time
import configparser
import subprocess
import sys
import datetime

current_tbanalysis_py_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(current_tbanalysis_py_path,"..","utils"))
from custom_logger import logger

"""
Pull tombstones from remote devices, and then deduplication, then merge
"""

local_tombstone_analysis_script_path = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(local_tombstone_analysis_script_path, "..", "fuzz.ini")
tombstones_remote_path = "/data/tombstones/"

# distinct hashes alread found
hashes_already_merged = []

global TARGET
global fuzz_target

def init_read_config_for_tombstone_analysis():
    global TARGET
    global fuzz_target
    config = configparser.ConfigParser()
    if not os.path.exists(config_path):
        logger.info("make sure you have a config(fuzz.ini) file in the framework-fuzz/tools/ folder ")

    config.read(config_path)
    TARGET = config.get('FUZZ_TARGET', 'TARGET').replace(".so","")
    # SET THIS VARIABLE BEFORE RUN.
    # THIS IS TO DIFFER FUZZERS
    fuzz_target = TARGET.strip()


def stop_tombstone_analysis_handler():
    logger.info("Tombstone Analysis will exit")
    sys.exit(1)


def analyze_tombstone(tombstone_dir):
    """
    analyze a tombstone file and generate a hash
    """
    hashes_dict = {}
    hashes = []
    
    for filename in os.listdir(tombstone_dir):
        crash_hash = ""
        if filename.endswith(".pb"):
            continue
        try:
            with open(os.path.join(tombstone_dir, filename),"r",errors='ignore') as f:
                content = f.read()
                sections = content.split("\n\n")

                # 0. find bt index
                for i in range(0, len(sections)):
                    if "backtrace:\n" in sections[i]:
                        bt_idx = i
                        break

                # 1. get backtrace
                for backtrace in sections[bt_idx].split("\n")[:10]:

                    # #00 pc 000000000007066c  /apex/com.android.runtime/lib64/bionic/libc.so (abort+160) (BuildId: b91c775ccc9b0556e91bc575a2511cd0)
                    backtrace_segments = backtrace.lstrip().split(" ")
                    # delete empty string in the list
                    backtrace_segments = list(filter(None, backtrace_segments))
                    # do not need address info
                    backtrace_segments = backtrace_segments[3:]

                    crash_hash += " ".join(backtrace_segments)

                md5 = hashlib.md5()
                md5.update(crash_hash.encode("utf-8"))
                hash = md5.hexdigest()
                if hash not in hashes:
                    hashes_dict[filename] = hash
                    hashes.append(hash)
            
        except Exception as e:
            logger.info("Exception {} , file name is {}".format(e,os.path.join(tombstone_dir, filename)))        

    # delete useless tombstone files in the folder
    useful_files = []
    for file in hashes_dict:
        useful_files.append(file)

    for file in os.listdir(tombstone_dir):
        if file not in useful_files:
            os.unlink(os.path.join(tombstone_dir, file))

    return hashes_dict


def pull_tombstones_from_remote(device):
    """
    pull all tombstones from remote device
    """
    pull_cmd = "adb -s {} pull {} {}".format(
        device.serial, tombstones_remote_path, os.path.join(local_tombstone_analysis_script_path, fuzz_target+device.serial))
    proc = subprocess.Popen(pull_cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()

    # delete previous tombstones
    rm_cmd = "adb -s {} shell rm {}".format(
        device.serial, os.path.join(tombstones_remote_path, "*"))
    proc = subprocess.Popen(rm_cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    # kill tombstoned and it will restart
    # 目的是防止tombstones的序号过大（不知是否会产生异常），但要注意这里kill的时候有可能会出现短暂的crash不能捕获的情况
    kill_cmd = "adb -s {} shell pkill tombstoned ".format(device.serial)
    os.system(kill_cmd)


def merge_tombstones(device, hashes_dict):
    """
    merge tombstones files from different devices into one folder
    """
    merged_path = os.path.join(local_tombstone_analysis_script_path, fuzz_target+"-TOTAL")
    global hashes_already_merged


    # 首先收集历史崩溃
    for crash_file in os.listdir(merged_path):
        hash = crash_file.split("-")[-1].strip()
        if hash not in hashes_already_merged:
            hashes_already_merged.append(hash)
    
    if not os.path.exists(merged_path):
        os.system("mkdir {}".format(merged_path))
    for dir in os.listdir(local_tombstone_analysis_script_path):
        tb_dir = os.path.join(local_tombstone_analysis_script_path,dir)
        if os.path.isdir(tb_dir) and dir.find("TOTAL") < 0:
            if dir.startswith(fuzz_target+device.serial):
                for file in os.listdir(tb_dir):
                    if hashes_dict[file] in hashes_already_merged:
                        continue
                    else:
                        hashes_already_merged.append(hashes_dict[file])
                        now = datetime.datetime.now()
                        now = now.strftime("%Y-%m-%d-%H-%M-%S-")
                        shutil.copyfile(os.path.join(local_tombstone_analysis_script_path, dir, file), os.path.join(
                            merged_path, now + hashes_dict[file]))
            shutil.rmtree(tb_dir)


def entry_tombstones():
    while True:
        try:
            client = AdbClient(host="127.0.0.1", port=5037)
            devices = client.devices()
            for device in devices:
                # clear previous data
                if os.path.exists(os.path.join(local_tombstone_analysis_script_path, fuzz_target+device.serial)):
                    os.popen(
                        "rm -rf {}".format(os.path.join(local_tombstone_analysis_script_path, fuzz_target+device.serial)))
                # pull from remote
                pull_tombstones_from_remote(device)
                # deduplication
                hashes_dict = analyze_tombstone(os.path.join(
                    local_tombstone_analysis_script_path, "{}".format(fuzz_target+device.serial)))
                # merge tombstones
                merge_tombstones(device, hashes_dict)
                # pull remote target file for further analysis
                merged_path = os.path.join(local_tombstone_analysis_script_path, fuzz_target+"-TOTAL")
                # remove last fuzzing temporary folder
                cmd = "rm -rf {}".format(os.path.join(merged_path, device.serial))
                # logger.info(cmd)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
                output = proc.communicate()
                # pull latest fuzzing folder
                pull_cmd = "adb -s {} pull {} {}".format(device.serial, os.path.join(
                    "/data/local/tmp/", fuzz_target), os.path.join(merged_path, device.serial))
                os.popen(pull_cmd)

            # count how many different tombstones are found in different devices
            num_of_crashes = 0
            for f in os.listdir(merged_path):
                if not os.path.isdir(os.path.join(merged_path, f)):
                    num_of_crashes += 1
            logger.warning("{} crashes are found, and are stored in {}.".format(num_of_crashes, merged_path))
        except Exception as e:
            logger.info("Expection {}".format(e))
        
        time.sleep(10)
        # the following part is used to help raise exception if the device is not connectable
        client = AdbClient(host="127.0.0.1", port=5037)
        devices = client.devices()


if __name__ == "__main__":
    init_read_config_for_tombstone_analysis()
    entry_tombstones()
