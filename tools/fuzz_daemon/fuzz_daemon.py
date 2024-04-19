#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   daemon.py
@Time    :   2022/08/11
@Author  :   @Puzzor 
@Version :   1.0
@Contact :   puzzorsj@gmail.com
@Desc    :   此脚本是控制afl-fuzz的主入口
'''

# here put the import lib

import os
from ppadb.client import Client as AdbClient
import threading
import time
import hashlib
import configparser
import signal
import pdb
import sys
import subprocess
import struct

current_fuzzdaemon_py_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(current_fuzzdaemon_py_path,"..","tombstones_analysis"))
from tombstones_analysis import *

sys.path.append(os.path.join(current_fuzzdaemon_py_path,"..","utils"))
from custom_logger import logger

global TARGET
global config
global remote_file_to_rewrite
global transaction_start
global transaction_stop
global afl_in_dir
global afl_out_dir
global remote_minicorpus_dir
global config_path
global afl_fuzz
global cmd_template
global target_dir
global target_file
global manager_path
global threads

# # Default is "127.0.0.1" and 5037
# client = AdbClient(host="127.0.0.1", port=5037)
# devices = client.devices()



# afl-fuzz and seeds should in this dir
working_base_dir = "/data/local/tmp/"



def read_fuzz_config_for_fuzz():
    global TARGET
    global config
    global remote_file_to_rewrite
    global transaction_start
    global transaction_stop
    global afl_in_dir
    global afl_out_dir
    global remote_minicorpus_dir
    global config_path
    global afl_fuzz
    global cmd_template
    global target_dir
    global target_file
    global manager_path

    config_path = os.path.join(current_fuzzdaemon_py_path, "..", "fuzz.ini")
    config = configparser.ConfigParser()
    if not os.path.exists(config_path):
        logger.warning(" make sure you have a config(.ini) file in the framework-fuzz/tools/ folder ")

    config.read(config_path)
    TARGET = config.get('FUZZ_TARGET', 'TARGET')
    target_file = TARGET

    possible_path = os.path.join(current_fuzzdaemon_py_path, TARGET, TARGET+".so")
    if os.path.exists(possible_path):
        target_file += ".so"


    # first call code
    transaction_start = int(config.get(TARGET, 'SERVICE_FIRST_CALL'))
    # last call code+1
    transaction_stop = int(config.get(TARGET, 'SERVICE_LAST_CALL'))+1


    if target_file.endswith(".so"):
        # For .so file
        target_dir = target_file[:-3]+"/"
        remote_file_to_rewrite = "/system/lib64/{}".format(target_file)
    else:
        # For ELF
        target_dir = target_file+"/"
        remote_file_to_rewrite = "/system/bin/{}".format(target_file)
    
    afl_in_dir = os.path.join(working_base_dir, target_dir, "in")
    afl_out_dir = os.path.join(working_base_dir, target_dir, "out")
    remote_minicorpus_dir = os.path.join(working_base_dir, target_dir, "mini_corpus/")
    manager_path = os.path.join(working_base_dir, "android-wp-manager")
    config_path = os.path.join(working_base_dir, target_dir, "config.prop")
    afl_fuzz = os.path.join(working_base_dir, "afl-fuzz")
    cmd_template = "cd {} && nohup {} -i {} -o {} -s {} -e {} -m none -t 10000 -- {}  {}  @@ &".format(
    working_base_dir, afl_fuzz, afl_in_dir, afl_out_dir, transaction_start, transaction_stop, manager_path, config_path)

def build_config():
    global TARGET
    global config
    # build the config.prop file according to ini file
    with open(os.path.join(TARGET, "config.prop"), "w", newline="\n") as f:
        f.write("SERVICE_NAME:{}\n".format(config.get(TARGET, 'SERVICE_NAME')))
        f.write("INTERFACE_TOKEN:{}\n".format(
            config.get(TARGET, 'INTERFACE_TOKEN')))
        f.write("SERVICE_FIRST_CALL:{}\n".format(
            config.get(TARGET, 'SERVICE_FIRST_CALL')))
        f.write("SERVICE_LAST_CALL:{}\n".format(
            config.get(TARGET, 'SERVICE_LAST_CALL')))
        f.write("IS_SA:{}\n".format(config.get(TARGET, 'IS_SA')))

def getmd5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def prepare_for_fuzz(device,from_locate_service=False):
    """
    """
    cmd = "adb -s {} root".format(device.serial)
    os.popen(cmd)
    cmd = "adb -s {} remount".format(device.serial)
    os.popen(cmd)

    # clear_path = os.path.join(working_base_dir, target_dir)
    # cmd = "rm -rf {}".format(clear_path)
    # device.shell(cmd)

    cmd = "rm -rf {}/*".format(working_base_dir)
    device.shell(cmd)

    # copy original target file to local for backup
    if not from_locate_service:
        original_path = os.path.join(
            current_fuzzdaemon_py_path, target_dir, target_file+".raw")
        if not os.path.exists(original_path):
            device.pull(remote_file_to_rewrite, original_path)

    # push target file to overwite remote
    
    cmd = "adb -s {} push {} {}".format(device.serial, os.path.join(current_fuzzdaemon_py_path,target_dir, target_file), remote_file_to_rewrite)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()

    # push local dir to remote
    cmd = "adb -s {} push {} {}".format(device.serial,os.path.join(current_fuzzdaemon_py_path,target_dir), working_base_dir)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()

    # if target file is ELF, we may consider pkill the  process and then overwrite the target
    if not target_file.endswith(".so"):
        for i in range(0, 10):
            # try 10 times, since even we use pkill, there is still chance that text busy happens
            cmd = "adb -s {} shell \" pkill {} && cp {} {} \" ".format(device.serial, target_file, os.path.join(
                working_base_dir, target_file, target_file), remote_file_to_rewrite)
            os.system(cmd)

    # push afl-fuzz and manager
    device.push("{}".format(os.path.join(current_fuzzdaemon_py_path, "afl-fuzz")),
                os.path.join(working_base_dir, "afl-fuzz"))

    device.push("{}".format(os.path.join(current_fuzzdaemon_py_path, "android-wp-manager")),
                os.path.join(working_base_dir, "android-wp-manager"))

    # chmod +x
    cmd = "chmod +x {}".format(os.path.join(working_base_dir, "afl-fuzz"))
    device.shell(cmd)

    cmd = "chmod +x {}".format(os.path.join(working_base_dir,
                               "android-wp-manager"))
    device.shell(cmd)
    if not from_locate_service:
        device.shell("reboot")


def mini_corpus(device, isFirstDevice=False):
    """
    work same as afl-cmin
    """
    logger.info("Mini corpus")
    
    

    local_mini_corpus = os.path.join(current_fuzzdaemon_py_path, target_dir, "mini_corpus/")

    if isFirstDevice:

        if os.path.exists(local_mini_corpus):
            os.system("rm -rf {}".format(local_mini_corpus))
            # os.system("mkdir {}".format(local_mini_corpus))

        # Find historical queue path from ../tombstones_analysis, nasty code: those queue files shouldn't be stored in tombsotones_analysis folder
        tombstones_analysis_folder = os.path.join(
            current_fuzzdaemon_py_path, "..", "tombstones_analysis")
        for ta in os.listdir(tombstones_analysis_folder):
            # incase target is a .so file
            if ta.startswith(target_file.split(".")[0]):
                for single_fuzzer_dir in os.listdir(os.path.join(tombstones_analysis_folder, ta)):
                    if not os.path.isdir(os.path.join(tombstones_analysis_folder, ta, single_fuzzer_dir)):
                        continue
                    logger.info("Find previous fuzzing data, will copy historical queue path from {}".format(
                        single_fuzzer_dir))
                    queue_path = os.path.join(
                        tombstones_analysis_folder, ta, single_fuzzer_dir, "out", "queue")
                    if not os.path.exists(queue_path):
                        continue
                    for queue_file in os.listdir(queue_path):
                        if queue_file.find("id") < 0:
                            continue
                        seed_path = os.path.join(queue_path, queue_file)
                        seed_md5 = getmd5(seed_path)
                        # copy to current in folder
                        cmd = "cp {} {}".format(seed_path, os.path.join(
                            current_fuzzdaemon_py_path, target_dir, "in", seed_md5))
                        os.popen(cmd)

        logger.info("Start to minimize seed corpus on {}".format(device.serial))

        cmd = "adb -s {} root".format(device.serial)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()

        # turn off selinux
        cmd = "adb -s {} shell setenforce 0".format(device.serial)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()

        cmd = "adb -s {} push {} {}".format(device.serial, os.path.join(
            current_fuzzdaemon_py_path, "afl-showmap"), os.path.join(working_base_dir, "afl-showmap"))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()

        cmd = "adb -s {} shell chmod +x {}".format(
            device.serial, os.path.join(working_base_dir, "afl-showmap"))
        os.system(cmd)

        cmd = "mkdir {}".format(remote_minicorpus_dir)
        # print(cmd)
        device.shell(cmd)

        # run afl-showmap to get bitmap
        for seed in os.listdir(os.path.join(current_fuzzdaemon_py_path, target_dir, "in")):
            afl_showmap = os.path.join(working_base_dir, "afl-showmap")
            cmd = "{} -o {} -t 10000 -m none -- {} {} {}".format(afl_showmap,
                                                                 os.path.join(remote_minicorpus_dir, seed), manager_path, config_path, os.path.join(afl_in_dir, seed))
            device.shell(cmd)
            time.sleep(0.2)

        # copy back the trace to analyze
        cmd = "adb -s {} pull {} {}".format(device.serial,
                                            remote_minicorpus_dir, os.path.join(current_fuzzdaemon_py_path, target_dir))

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()

        # analyze the traces
        mini_corpus_dict = {}
        useful_files = []

        for candidate in os.listdir(local_mini_corpus):
            f_path = os.path.join(local_mini_corpus, candidate)
            # nasty method
            md5_str = getmd5(f_path)
            if md5_str not in mini_corpus_dict:
                mini_corpus_dict[md5_str] = f_path
                useful_files.append(candidate)

        # delete useless file
        for seed in os.listdir(os.path.join(current_fuzzdaemon_py_path, target_dir, "in")):
            if seed not in useful_files:
                os.remove(os.path.join(current_fuzzdaemon_py_path, target_dir, "in", seed))

    # delete remote trace files, there may have no trace files
    cmd = "adb -s {} shell rm -rf {}".format(device.serial, remote_minicorpus_dir)
    os.system(cmd)

    # delete local trace
    os.system("rm -rf {}".format(local_mini_corpus))

    # delete remote seeds first
    cmd = "adb -s {} shell rm -rf {}".format(device.serial, afl_in_dir)
    os.system(cmd)

    
    # copy minimized corpus to remote
    cmd = "adb -s {} push {} {}".format(device.serial,
                                        os.path.join(current_fuzzdaemon_py_path, target_dir, "in"), afl_in_dir)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()


def aflfuzz(device):
    # prepare to fuzz
    logger.info("{} - Prepare for fuzz".format(device.serial))

    if target_file.endswith(".so"):
        # stop && start
        cmd = "adb -s {} shell \"stop&&start\"".format(device.serial)
        os.popen(cmd)
        time.sleep(20)

    afl_prepare_cmd = "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor"
    device.shell(afl_prepare_cmd)

    cmd = "pkill afl-fuzz"
    device.shell(cmd)

    cmd = "settings put secure hw_suw_frp_state 0"
    device.shell(cmd)

    cmd = "pm disable com.huawei.hwstartupguide"
    device.shell(cmd)

    cmd = "rm -rf /data/tombstones/*"
    device.shell(cmd)

    # set tombstones prop
    tombstones_cmd = "setprop tombstoned.max_tombstone_count 999999".format(
        device.serial)
    device.shell(tombstones_cmd)

    # trigger the process to  restart to load new prop
    cmd = "pkill tombstoned".format(device.serial)
    device.shell(cmd)

    # mute
    cmd = "input keyevent 164"
    device.shell(cmd)

    # remount for write
    cmd = "adb -s {} remount".format(device.serial)
    os.popen(cmd)

    # start to fuzz
    logger.info("{} - Start to fuzz".format(device.serial))
    # set a timeout to prevent stuck here
    try:
        device.shell(cmd_template, timeout=3)
        # cmd = "adb -s {} shell \" {} \"".format(device.serial,cmd_template)
        # print(cmd)
        # os.system(cmd)
    except Exception as e:
        logger.info("{} - aflfuzz - Exception: {}".format(device.serial, e))


def check_status(device):
    """
    用于检测手机状态是否正常。
    由于在一些fuzz过程中，可能目标程序挂掉且挂掉之后不会自动重启，因此需要定期监控目标是否仍在运行
    或者其他的检测；注意这里需要根据不同的目标进行定制
    """
    global threads 

    while True:
        time.sleep(2)
        # 监控每个设备当前的Fuzz状态并显示
        # 1. afl-fuzz是否正在运行
        # 2. 当前跑出多少个path
        # 3. 当前的bitmap覆盖是多少

        output = device.shell("ps -A|grep afl-fuzz")

        monitor_str = ""

        if len(output) > 5:
            monitor_str += "{} AFL is running, ".format(
                device.serial)
            # 开启新线程来监控 tombstones
            if len(threads)<2:
                init_read_config_for_tombstone_analysis()
                t2 = threading.Thread(target=entry_tombstones)
                t2.start()
                threads.append(t2)

        else:
            monitor_str += "{} AFL is DOWN, ".format(device.serial)
            # try to run afl again
            try:
                device.shell(cmd_template, timeout=3)
            except Exception as e:
                logger.warning(e)

        output = device.shell(
            "ls -l {} |wc -l".format(os.path.join(afl_out_dir, "queue")))
        queue_count = 0
        try:
            queue_count = int(output.strip())
        except:
            logger.warning("queue path is not ready")
        monitor_str += " Current path is {}, ".format(queue_count)

        cmd = "cat {} |grep bitmap_cvg".format(
            os.path.join(afl_out_dir, "fuzzer_stats"))
        bitmap_cvg = output = device.shell(cmd)
        if bitmap_cvg.find("directory") >= 0:
            bitmap_cvg = "not-ready"
        monitor_str += " Current bitmap_cvg is {} ".format(
            bitmap_cvg.split(" ")[-1].strip())

        logger.info(monitor_str)

        # # 检测目标是否挂掉，并需要重启之类的
        # try:
        #     ps_output = device.shell("ps -A|grep -i simpleperfserver")
        #     # logger.info("{} - daemon checking".format(device.serial))
        #     if len(ps_output) > 10:
        #         # 说明有进程存在
        #         pass
        #     else:
        #         print(
        #             "********** {} - target server is down, restart".format(device.serial))
        #         os.popen(
        #             "adb -s {} shell simpleperfserver &".format(device.serial))

        # except Exception as e:
        #     logger.info("{} - daemon - Exception: {}".format(device.serial, e))


def reboot():
    for device in devices:
        cmd = "adb -s {} reboot".format(device.serial)
        os.popen(cmd)


def restore():
    """
    restore official target
    """
    logger.warning("Will Restore")
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        cmd = "adb -s {} root".format(device.serial)
        os.popen(cmd)
        cmd = "adb -s {} remount".format(device.serial)
        os.popen(cmd)

        original_path = os.path.join(
            current_fuzzdaemon_py_path, target_dir, target_file+".raw")
        if os.path.exists(original_path):
            cmd = "adb -s {} push {} {}".format(device.serial,
                                                original_path, remote_file_to_rewrite)
            print(cmd)
            os.system(cmd)

        cmd = "adb -s {} settings put secure hw_suw_frp_state 0".format(
            device.serial)
        device.shell(cmd)

        cmd = "adb -s {} pm disable com.huawei.hwstartupguide".format(
            device.serial)
        device.shell(cmd)
        logger.warning("Restore -- reboot")
        cmd = "adb -s {} reboot".format(device.serial)
        os.popen(cmd)
    


def ctrl_c_handler(signum, frame):
    logger.warning(" Ctrl+C detected, will restore original file")
    restore()


def fuzz_start(from_locate_service=False): 

    global threads 

    threads = []
    isFristDevice = True
    
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        prepare_for_fuzz(device,from_locate_service=from_locate_service)
    
    if not from_locate_service:
        logger.info("Wait for reboot")
        time.sleep(60)
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    for device in devices:
        mini_corpus(device, isFristDevice)
        isFristDevice = False
        aflfuzz(device)
        t1 = threading.Thread(target=check_status, args=(device,))
        threads.append(t1)
        t1.start()

    for th in threads:
        th.join()



if __name__ =="__main__":
    read_fuzz_config_for_fuzz()
    build_config()
    signal.signal(signal.SIGINT, ctrl_c_handler)
    fuzz_start()