#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   main.py
@Time    :   2022/08/11
@Author  :   @Puzzor 
@Version :   1.0
@Contact :   puzzorsj@gmail.com
@Desc    :   None

# 1. 扫描所有 ontransact函数的实现位置，并记录该文件名，确保framework-fuzz在external目录下，并且main.py在tools/auto_compilation目录下
# 2. 在编译过程中如果需要保留symbol，可以手工将build/soong/scripts/strip.sh中的 do_strip_keep_mini_debug_info 改为do_strip_keep_symbols
# 3. TODO 删除.bp 中的tests以及tests目录
# 4. TODO 有些情況下同一目錄下可能存在多個cpp包含OnTransact函數，需要同時處理之後再編譯
# 5. TODO 有一些target是 compile_multilib":32的问题
# 6. 注意在某些情况下虽然有trace-pc-guard的flag，但是编译之后并没有进行插桩，这很有可能是某些编译选项造成的。
例如 在libaudioclient 的编译过程中，由于存在-fsanitize-cfi-cross-dso,导致编译出的文件没有进行插装（可通过对中间编译的文件使用llvm-dis -o - XXXX.o|grep trace_pc 来进行观察文件没有被trace-pc-guard插桩）
删除该编译选项后插装正常 （修复：在build/soong/cc/sanitize.go 中搜索 -fsanitize-cfi-cross-dso 和 -fsanitize=cfi 并删除，同时搜索c.sanitize.Properties.Sanitize.Cfi,把append附近的逻辑注释掉。这样编译出来的target会不带cfi）
注意这样的负面后果是如果有的.bp或者.mk中指明了sanitize的部分（比如在sanitize中指明cfi:true），则会编译出错，可能需要进一步对编译选项进行调整
7. 注意如果删除了cfi相关的编译选项，则需要同时把 build/soong/cc/config/cfi_exports.map 中大括号中的内容删除
8. 特别注意，如果目标是个.so文件，那么加载这个.so文件的ELF也一定要加trace-pc-guard，但是ELF不要加asan，否则可能会不正常（注意是可能，不一定），这是调试出来的问题，如果发现fuzz时候不正常了就需要注意一下
'''

# here put the import lib

import os
import pdb
import re
import sys
import shlex
from parsers.bpparser import BpParser
import subprocess
import time
import json

global compile_threads
global compilation_file_black_list
global first_transaction_code
global last_transaction_code
first_transaction_code = 1
last_transaction_code  = 65535

current_autocompile_py_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_autocompile_py_path,"..","fuzz_daemon"))
from fuzz_daemon import *
sys.path.append(os.path.join(current_autocompile_py_path,"..","tombstones_analysis"))
from tombstones_analysis import *

sys.path.append(os.path.join(current_autocompile_py_path,"..","utils"))
from custom_logger import logger

sys.path.append(os.path.join(current_autocompile_py_path,"..","ast_analysis"))
from analyze_transaction_code import dict_generator
from analyze_transaction_code import transaction_dict

sys.path.append(os.path.join(current_autocompile_py_path,"..","trace_pc_guard_patcher"))
from patcher import *





root_dir = os.path.join(current_autocompile_py_path, "../../../../")

root_dir = os.path.abspath(root_dir)
# 正常编译完成后输出文件所在的system目录
output_dir = os.path.join(root_dir, "out", "target",
                          "product", "generic_arm64", "system")  # AOSP

# output_dir = os.path.join(root_dir,"out","target","product","generic_a15","system") # HMOS

lunch_cmd = "lunch aosp_arm64"


# historical compiled targets in local directories
historical_compiled_targets = []

# compiled targets in current run
compiled_targets = []


# avoid raw sanitize, compilation will fail if with these options
sanitize_black_list = ["unsigned-integer-overflow","signed-integer-overflow","-fwhole-program-vtables","thin: true"]

compilation_file_black_list=[]

# compilation file path black list: we know some target does not need to be compiled
try:
    cpp_file_history = open(os.path.join(current_autocompile_py_path,"cpp_history.txt"),'r').readlines()
except:
    cpp_file_history = []


cpp_file_black_list = ["frameworks/native/libs/graphicsenv/IGpuService.cpp"]


def is_in_compilation_black_list(compilation_file_path):
    """Determine if compilation_file_path is in black list

    Args:
        compilation_file_path ([str]): [target compilation file path]
    """
    global compilation_file_black_list
    for black in compilation_file_black_list:
        if compilation_file_path.find(black)>=0:
            return True
        else:
            continue 
    return False

def read_historical_targets():
    """
    read historical compiled targets
    """
    global historical_compiled_targets
    if os.path.exists(os.path.join(current_autocompile_py_path, "Targets")):
        for target in os.listdir(os.path.join(current_autocompile_py_path, "Targets")):
            if os.path.isdir(os.path.join(current_autocompile_py_path, "Targets", target)):
                historical_compiled_targets.append(target)

def scan_and_modity_for_ontransact(file_path):
    """
    扫描包含Ontransact 函数实现的文件（目前这里传进来的只有cpp文件）

    在OnTransact函数中添加fuzz related 代码
    """
    pattern = re.compile(r'::onTransact\([^{;]*\n*[^{;]*\)[^{;]*{')  # 查找函数实现
    prepared_coveraged_str = """
    memset(__afl_area_ptr, 0, MAP_SIZE);
    __afl_area_ptr[0]=1;
    if (hssl::WpService::onTransact(code, data, reply) == android::NO_ERROR) {
        return android::NO_ERROR;
    }
    char *buffer = static_cast<char*>(malloc(data.dataSize()*2+1));
    char *ptr = buffer;
    memset(buffer,0,data.dataSize()*2+1);
    for(unsigned long i = 0; i< data.dataSize();i++){
        sprintf(ptr,"%02x", data.data()[i]);
        ptr+=2;
    }
    ALOGE("[FUZZ_TARGET::REPLACE::onTransact] Transaction Code: 0x%x (%d), Transaction Data: %s", code, code, buffer);
    """
    header_str = """#include \"service/WpService.h\"\n"""
    with open(file_path, encoding='utf-8', errors='ignore') as f:
        content = f.read()
        matches = pattern.findall(content)
        if len(matches) == 1:
            os.system("cp {} {}.autocompilation".format(file_path, file_path))
            # 增加内容
            content = open(file_path, "r").read()
            with open(file_path, "w") as f:
                write_idx = content.find(matches[0])
                content_lst = list(content)
                

                case_pattern = re.compile(r"case\s*(\w*.*)\n")
                tmp_content = content[write_idx:]
                case_matches = case_pattern.findall(tmp_content)
                if len(case_matches)>0:
                    first_case = case_matches[0]
                else:
                    first_case = "UNKNOWN"
                first_case = first_case.replace("{","")
                first_case = first_case[:first_case.rfind(":")]
                logger.info("Looking for transaction code with pure code analysis: {} in {}".format(first_case,file_path))
                locate_transaction_code(file_path,first_case)

                
                content_lst.insert(
                    write_idx+len(matches[0]), prepared_coveraged_str.replace("REPLACE",os.path.basename(file_path)))
                # write header 这里的inlude要放到最后一个再include
                content_str = "".join(content_lst)
                content_lst = content_str.split("\n")
                for i in range(len(content_lst)-1, 0, -1):
                    if content_lst[i].startswith("#include"):
                        content_lst.insert(i+1, header_str)
                        break
                new_content = ""
                for line in content_lst:
                    new_content += line
                    new_content += "\n"

                f.write(new_content)
            return True
        elif len(matches) > 1:
            logger.info("Please manually check the cpp file: {}".format(file_path))
            # pdb.set_trace()
            return False
        else:
            return False

def parser_bp_file(target_name="", bp_file_path=""):
    """
    解析bp文件，并添加fuzz相关部分
    """
    # bp file equipped with fuzz related part
    section_names = []
    defaults_in = False

    parser = BpParser()
    parser.parse(bp_file_path)
    datas = parser.data()
    for i in range(len(datas)):
        data = datas[i]
        data_name = data[0]
        data_keys = data[1].keys()

        # init new bp section
        section = {}
        section[data_name] = data[1]

        if "srcs" in data_keys:
            # 查找 target_name 是否在srcs中
            for sector in data[1]['srcs']:
                if target_name in sector:
                    # logger.info(data_name)
                    if data_name == "filegroup":
                        # 如果在filegroup 里则准备进行迭代寻找
                        target_name = data[1]['name']
                        # logger.info(target_name)
                        # 迭代寻找

                        # pdb.set_trace()
                        section_names, defaults_in = parser_bp_file(
                            target_name, bp_file_path)
                    elif data_name in ['cc_binary', 'cc_binary_static', 'cc_library', 'cc_binary', 'cc_library_shared', 'cc_library_static']:

                        section_name = data[1]['name']
                        if section_name not in section_names:
                            section_names.append(section_name)

                        data_dict = data[1]
                        if 'defaults' in data_dict:
                            defaults_in = True
                        else:
                            defaults_in = False
                        return section_names, defaults_in
    return section_names, defaults_in

def build_new_bp_file(new_bp_file_section_list, old_bp_file, defaults_in):

    # construct a new bp file, and mv original file to .autocompilation
    os.system("cp {} {}.autocompilation".format(old_bp_file, old_bp_file))

    raw_content = open(old_bp_file, "r").readlines()

    new_bp_file_handle = open(old_bp_file, "w")

    global sanitize_black_list

    j = -1
    for section in new_bp_file_section_list:
        for i in range(0, len(raw_content)):
            if i <= j:
                continue
            
            line = raw_content[i]
            
            is_in_black_list = False
            for b in sanitize_black_list:
                if line.find(b)>=0:
                    is_in_black_list = True
                    break
            if is_in_black_list:
                continue
            
            # 写入到新文件中
            new_bp_file_handle.write(raw_content[i])
            new_bp_file_handle.flush()

            if line.strip().find('name: "{}"'.format(section)) >= 0:
                InTargetSection = True
                if defaults_in:
                    # 有defaults，需要找到defaults

                    for j in range(i+1, len(raw_content)):
                        if raw_content[j][0] == "}":
                            InTargetSection = False
                        if InTargetSection:
                            pattern = re.compile("defaults:.*\[.*\]")
                            matches = pattern.findall(raw_content[j].strip())

                            # 说明defaults的定义在一行内完成
                            if len(matches) > 0:
                                # pdb.set_trace()
                                right_bracket_idx = raw_content[j].strip().rfind(
                                    "]")
                                tmp_content = raw_content[j].strip()[
                                    :right_bracket_idx]+","
                                tmp_content += '\n"android-wp-service-external-defaults",\n],\n'
                                new_bp_file_handle.write(tmp_content)
                                i = j+1
                            else:
                                # pdb.set_trace()
                                # 说明defaults的定义不在一行内完成
                                new_bp_file_handle.write(raw_content[j])
                                i = j+1
                                if raw_content[j].strip().find("defaults:") >= 0:
                                    # 找到了defaults
                                    # 插入一行
                                    new_bp_file_handle.write(
                                        '"android-wp-service-external-defaults",\n')
                                    new_bp_file_handle.flush()
                                    break
                        else:
                            new_bp_file_handle.write(raw_content[j])
                else:
                    # 没有 defaults,直接插入一个defaults
                    defaults = """defaults: ["android-wp-service-external-defaults",],\n"""
                    new_bp_file_handle.write(defaults)

    new_bp_file_handle.close()

def locate_service(local_target_file_path,local_target_path,is_sa=0,fuzz_duration=0):
    """Locating which service corresponding to current onTransact function
    For example, you know there is  onTransact function in frameworks/native/libs/graphicsenv/IGpuService.cpp, and you will  get
    SERVICE_NAME: gpu
    SERVICE_TOKEN:android.graphicsenv.IGpuService

    Args:
        local_target_file_path ([str]): [description]
        local_target_path ([str]): [description]
        is_sa (int, optional): [Is this a SA Service?]. Defaults to 0.
        fuzz_duration (int, optional): [how long do we need to fuzz this target after we locate the service name & token?]. Defaults to -1, means do not fuzz.
    """

    # # check if in history
    # try:
    #     history_file = open(os.path.join(current_autocompile_py_path,"history.txt"),"r")
    #     if os.path.basename(local_target_path) in history_file.read():
    #         history_file.close()
    #         return
    #     history_file.close()
    # except:
    #     pass

    global first_transaction_code
    global last_transaction_code

    proc = subprocess.Popen("adb start-server", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    proc = subprocess.Popen("adb root", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    proc = subprocess.Popen("adb remount", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()

    if local_target_file_path.endswith(".so"):
        if not os.path.exists("{}.raw".format(local_target_file_path)):
            # backup original file first
            cmd = "adb pull /system/lib64/{} {}.raw".format(os.path.basename(local_target_file_path),local_target_file_path)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
            output = proc.communicate()

        cmd = "adb push {} /system/lib64/".format(local_target_file_path)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
    else:
        if not os.path.exists("{}.raw".format(local_target_file_path)):
            # backup original file first
            cmd = "adb pull /system/bin/{} {}.raw".format(os.path.basename(local_target_file_path),local_target_file_path)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
            output = proc.communicate()

        cmd = "adb push {} /system/bin/".format(local_target_file_path)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
    
    os.system("adb shell 'reboot' ")
    time.sleep(2)
    # 这里可以改成非每个目标都重启一次，可以把所有目标都拷贝进去再重启？不过可能会由于中间某个目标的失败导致所有目标都失败？
    while True:
        proc = subprocess.Popen("adb devices", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()[0]
        if len(output.split(b"\n"))>3:
            time.sleep(20) # 这里还是要sleep一下，否则有些服务还没有启动完成； TODO  可以找一种方法判断系统服务启动完成
            break
            
    
    proc = subprocess.Popen("adb shell service list", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    
    services= output[0].split(b"\n")
    logger.info("Locating target service within {} services".format(len(services)))
    Found_Service = False
    for service in services[1:-1]:
        try:
            service=service.split(b"\t")[1]
            service_name = service.split(b": [")[0]
            # if service_name.find(b"com.huawei.security.IHwKeystoreService")<0:
            #     continue
            service_token = service.split(b": [")[1].strip().replace(b"]",b"")

            cmd = "adb logcat -G 2M"
            os.system(cmd)

            for i in range(0,5):
                # sometimes logcat -c may fail, so let's try more times
                clear_logcat_cmd = "adb shell logcat -c"
                os.system(clear_logcat_cmd)

            locate_logcat_cmd = "adb shell logcat"
            with open(os.path.join(current_autocompile_py_path,"tmp.txt"),"wb") as f:
                locate_proc = subprocess.Popen(locate_logcat_cmd.split(), stdout=f,stderr=f,bufsize=256)

            # logger.info("Testing service {}".format(service_name.decode("utf-8")))
            for i in range(0,1):
                call_service_cmd = "adb shell service call {} -1 i32 1".format(service_name.decode("utf-8"))
                
                call_service_cmd = "adb shell "
                service_call_payload = "service call {} -1 i32 1;".format(service_name.decode("utf-8"))
                call_service_cmd = call_service_cmd + service_call_payload*5
                proc = subprocess.Popen(call_service_cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
                output = proc.communicate(timeout=1)

            with open(os.path.join(current_autocompile_py_path,"tmp.txt"),"rb") as f:
                output = f.read()

            locate_proc.kill()

            if output.find(b"Transaction Code: 0xffffffff")>=0:
                logger.warning("Found service {} {}".format(service_name.decode("utf-8"),service_token.decode("utf-8")))
                Found_Service = True
                # build a common configuration file in local folder
                with open(os.path.join(local_target_path,"config.prop"),"w",newline="\n") as f:
                    f.write("SERVICE_NAME:{}\n".format(service_name.decode("utf-8")))
                    f.write("INTERFACE_TOKEN:{}\n".format(service_token.decode("utf-8")))
                    f.write("SERVICE_FIRST_CALL:{}\n".format(first_transaction_code)) 
                    f.write("SERVICE_LAST_CALL:{}\n".format(last_transaction_code)) # TODO NASTY code
                    f.write("IS_SA:{}\n".format(is_sa))
                break
        except Exception as e:
            logger.info("Error in locating service: {}".format(e))

    # restore original file
    proc = subprocess.Popen("adb root", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    proc = subprocess.Popen("adb remount", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    if local_target_file_path.endswith(".so"):
        cmd = "adb push {}.raw /system/lib64/{}".format(local_target_file_path,os.path.basename(local_target_file_path))
        # logger.info(cmd)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
    else:
        cmd = "adb push {}.raw /system/bin/{}".format(local_target_file_path,os.path.basename(local_target_file_path))
        # logger.info(cmd)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
    
    # # save history to file
    # history_file = open(os.path.join(current_autocompile_py_path,"history.txt"),"a+")
    # history_file.write(os.path.basename(local_target_path))
    # history_file.write("\n")
    # history_file.close()

    # do we need to fuzz it?
    if fuzz_duration > 0 and Found_Service:
        signal.signal(signal.SIGINT, wrapper_timeout_control)

        # 0. copy folder to ../fuzz_daemon
        os.system("rm -rf {}".format(os.path.join(current_autocompile_py_path,"..","fuzz_daemon",os.path.basename(local_target_path))))
        # 1. prepare for seeds
        os.system("mkdir {}".format(os.path.join(current_autocompile_py_path,"..","fuzz_daemon",os.path.basename(local_target_path))))
        os.system("cp -r {}/* {}".format(local_target_path,os.path.join(current_autocompile_py_path,"..","fuzz_daemon",os.path.basename(local_target_path))))
        os.system("mkdir {}".format(os.path.join(current_autocompile_py_path,"..","fuzz_daemon",os.path.basename(local_target_path),"in")))
        
        # pdb.set_trace()
        # we need to build a default seeds to increase efficiency
        for code in range(first_transaction_code, last_transaction_code):
            tcode_content = struct.pack("<i", code) 
            seed_path = os.path.join(current_autocompile_py_path,"..","fuzz_daemon",os.path.basename(local_target_path),"in")
            with open(os.path.join(seed_path, "default_{}_seed.bin".format(code)),"wb") as f:
                f.write(tcode_content)

        # 1. prepare fuzz.ini
        content = \
'''[FUZZ_TARGET]
TARGET={}
[{}]
{}
'''
        with open(os.path.join(local_target_path,"config.prop"),"r") as f:
            content_part = f.read()
        content = content.format(os.path.basename(local_target_file_path),os.path.basename(local_target_file_path),content_part)
        with open(os.path.join(current_autocompile_py_path,"..","fuzz.ini"),"w") as f:
            f.write(content)
        global compile_threads
        compile_threads = []
        # 2. call function from ../fuzz_daemon
        read_fuzz_config_for_fuzz()
        t1 = threading.Thread(target=timeout_control,args=(fuzz_duration,))
        t1.start()
        t2 = threading.Thread(target=fuzz_start,args=(True,))
        t2.start()
        compile_threads.append(t1)
        compile_threads.append(t2)
        for t in compile_threads:
            t.join()
        

def wrapper_timeout_control(signum, frame):
    timeout_control(1)
    
def timeout_control(timeout=0):
    """control fuzzing timeout in locate_service
    """
    logger.info("Fuzzing Timeout Controller in locate_service Set To {} Seconds".format(timeout))
    if timeout == 0:
        return
    else:
        time.sleep(timeout)
        logger.info("Trigger sigkill")
        # we will restore the target with official one, and then reboot the device
        # during reboot, there will be exception raised in tombstone analysis thread and fuzz_daemon thread
        # then, the threads will be exited
        restore()
        os.system("adb kill-server")
        time.sleep(15)

def restore_raw():
    proc = subprocess.Popen("adb root", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    proc = subprocess.Popen("adb remount", stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    
    if not os.path.exists(os.path.join(current_autocompile_py_path,"Targets")):
        return
        
    for folder in os.listdir(os.path.join(current_autocompile_py_path,"Targets")):
        if folder.startswith("lib"):
            lib_file_path = os.path.join(current_autocompile_py_path,"Targets",folder,folder+".so.raw")
            cmd = "adb push {} /system/lib64/{}.so".format(lib_file_path,folder)
            proc = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            proc.communicate()
        else:
            bin_file_path = os.path.join(current_autocompile_py_path,"Targets",folder,folder+".raw")
            cmd = "adb push {} /system/bin/{}".format(bin_file_path,folder)
            proc = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            proc.communicate()

def build_new_mk_file(old_mk_file_path):
    
    """
    Append fuzzing related commands to the .mk file
    """
    # construct a new mk file, and mv original file to .autocompilation
    os.system("cp {} {}.autocompilation".format(
        old_mk_file_path, old_mk_file_path))

    str_to_append = """
    # Use this part for every fuzzing target
    LOCAL_CFLAGS += -fsanitize-coverage=trace-pc-guard
    LOCAL_CFLAGS += -fsanitize=address
    LOCAL_LDFLAGS += -fsanitize=address
    LOCAL_C_INCLUDES += \
        external/framework-fuzz
    LOCAL_C_INCLUDES += external/framework-fuzz/tools/AFL
    LOCAL_STATIC_LIBRARIES += \
        android-wp-service-static
    LOCAL_STATIC_LIBRARIES += \
        afl-llvm-rt
    """
    global sanitize_black_list

    old_content = open(old_mk_file_path, "r").readlines()
    new_content=""

    for i in range(0, len(old_content)):


        # avoid raw sanitize compilation option
        is_in_black_list = False
        for b in sanitize_black_list:
            if old_content[i].find(b)>=0:
                is_in_black_list = True
                break
        if is_in_black_list:
            continue

        if old_content[i].replace(" ", "").find("include$(BUILD_SHARED_LIBRARY)") >= 0\
                or old_content[i].replace(" ", "").find("include$(BUILD_EXECUTABLE)") >= 0:
            new_content+=str_to_append
            new_content+=old_content[i]
            logger.info("  Inserted")
            # 可能出现多次，不要直接break
            # break
        else:
            new_content+=old_content[i]

    target = []
    for i in range(0, len(old_content)):
        if old_content[i].replace(" ", "").find("LOCAL_MODULE:=") >= 0:
            target.append(old_content[i].replace(
                " ", "").split(":=")[1].strip())

    with open(old_mk_file_path, "w") as f:
        f.write(new_content)

    return target

def compile_target(bp_file_path, extract_transaction={"extract":False,"cpp_file_name":"","cpp_file_path":""}):
    """
    compile for the target.
    """
    global first_transaction_code
    global last_transaction_code
    global transaction_dict

    # delete verbose*.tar.gz in AOSP output dir first
    aosp_output_dir = os.path.join(root_dir, "out")  # AOSP build output folder
    del_verbose_cmd = "rm {}".format(os.path.join(aosp_output_dir,"verbose*"))
    proc = subprocess.Popen(del_verbose_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()

    build_dir = os.path.dirname(bp_file_path)

    cmd = "source {}/build/envsetup.sh && {} && cd {} && mm".format(
        root_dir, lunch_cmd, build_dir)
    logger.info("  Building the target for {}".format(bp_file_path))
    
    cmd = "env -i /bin/bash -c '{}'".format(cmd)
    # logger.info(cmd)
    
    cmd = shlex.split(cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    normal_compile_output = proc.communicate()

    # extract transaction value 
    if(extract_transaction['extract']):
        # 0. we need to find out the command line to compile target cpp file.
        #    The cmdline is saved in $AOSP/out/verbose.tar.gz
        verbose_cmd_path = os.path.join(aosp_output_dir,"verbose.log.gz")
        # 1. extract verbose.log
        extract_verbose_cmd = "cd {} && gzip -d {}".format(aosp_output_dir,verbose_cmd_path)
        proc = subprocess.Popen(extract_verbose_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
        # 2. read verbose.log and find the cmd to build target cpp
        cpp_file_name = extract_transaction['cpp_file_name']
        verbose_log_path = os.path.join(aosp_output_dir,"verbose.log")
        cmd_to_build_cpp = ""

        with open(verbose_log_path,"r") as f:
            for line in f.readlines():
                if line.strip().endswith(cpp_file_name) or line.strip().endswith(cpp_file_name+'"') :
                    cmd_to_build_cpp = line.strip()
                    break
        if len(cmd_to_build_cpp)>0:
            cmd_to_build_cpp = cmd_to_build_cpp[cmd_to_build_cpp.find("prebuilts/"):]
        
        else:
            logger.warning("Did not find cmdline to build target cpp in verbose.log")

            
            # pdb.set_trace()
            # did not find cmd line to build target cpp, sth error occurs, just return previous build output
            return normal_compile_output[0]
        
        # 3. construct a new cmd to get ast
        # pdb.set_trace()
        # # find -o and its param
        # cmd_to_build_cpp_lst=cmd_to_build_cpp.split(" ")
        # o_idx = cmd_to_build_cpp_lst.index("-o")
        # del cmd_to_build_cpp_lst[o_idx:o_idx+2]


        cmd_to_build_cpp = cmd_to_build_cpp.split(" ")[0] + " -fsyntax-only -Xclang -ast-dump=json " + " ".join(cmd_to_build_cpp.split(" ")[1:])
        cmd_to_build_cpp = "cd {} && {}".format(root_dir,cmd_to_build_cpp)
        if cmd_to_build_cpp.endswith('"'):
            cmd_to_build_cpp = cmd_to_build_cpp[:-1]
        logger.info("Building AST with clang for {}".format(cpp_file_name))
        AST_JSON_FILE = os.path.join("/tmp/",cpp_file_name+".json")
        AST_JSON_FILE_HANDLE = open(AST_JSON_FILE,"w")
        
        proc = subprocess.Popen(cmd_to_build_cpp, stdout=AST_JSON_FILE_HANDLE, stderr=subprocess.PIPE,shell=True)
        output = proc.communicate()
        # TODO sometimes, clang will fail for AST analysis, we should check if it successes
        if len(output[1])>0:
            logger.warning("AST analysis with clang FAILS for {}".format(extract_transaction['cpp_file_name']))
            logger.warning("Using code analyzed in previous function")

            # first_transaction_code = 1
            # last_transaction_code  = 65535
            # return normal_compile_output[0]
            # pdb.set_trace()
            return normal_compile_output[0]

        
        AST_JSON_FILE_HANDLE.close()

        # 4.parse file and get result
        logger.info("Openning the AST file")
        content =open(AST_JSON_FILE,"r").read()
        logger.info("Loading the content to a json object")
        ast_json = json.loads(content)
        logger.info("Parsing the AST")
        for i in dict_generator(ast_json):
            pass

        # locate_transaction_code(extract_transaction['cpp_file_name'])
    trans_codes=[]
    for name in transaction_dict:
        trans_codes.append(int(transaction_dict[name]))

    # it is possible that the trans_codes be [] here, so if its len() is 0, initialize it 
    if len(trans_codes) == 0:
        return normal_compile_output[0]

    first_transaction_code=min(trans_codes)

    # SHELL_COMMAND_TRANSACTION : 1598246212 ? notice this
    # TODO sometimes, the transaction code is not consecutive, so should improve it
    last_transaction_code=max(trans_codes)
    
    
    if last_transaction_code in [1598246212]:
        trans_codes.sort()
        last_transaction_code = trans_codes[-2]+1

    # pdb.set_trace()
    return normal_compile_output[0]
    # return normal_compile_output[0]

def restore_autocompilation_files():
    backup_ext = ".autocompilation"
    logger.warning("Restoring files in case of previous tmp interruption")
    for root, dirs, files in os.walk(root_dir):
        for name in files:
            # except .repo and out folder
            if root.find(os.path.join(root_dir,"out"))>=0 \
            or root.find(os.path.join(root_dir,".repo"))>=0\
            or root.find(os.path.join(root_dir,"prebuilts"))>=0:
                continue
            if name.endswith(backup_ext):
                # copy back to original
                autocomp_path = os.path.join(root, name)
                raw_path = os.path.join(root, name[:name.rfind(".")])

                if autocomp_path == raw_path+backup_ext:
                    os.system("cp {} {}".format(autocomp_path, raw_path))

def is_historical_compiled(targets: list, historical_compiled_targets: list):
    """
    check if there is an element in historical_compiled_targets
    """
    historical_compiled = False
    # for section in targets:
    #     if section in historical_compiled_targets:
    #         historical_compiled = True
    return historical_compiled

def process_one_target(cpp_path,fuzz_duration=0):

    FoundCompilationFile = False
    FoundOnTransactFunction = False
    # 0. 排除历史已经编译过的目标
    file_path = os.path.split(cpp_path)[0]
    last_file_path = os.path.split(file_path)[1]
    if (last_file_path in historical_compiled_targets):
        return False, False
        # logger.info("@@@@@@@@@@  Skipping historical targets: {}".format(cpp_path))

    # 1.找出包含onTransact函数实现的cpp
    # 如果有.autocompilation，则先恢复原有的bak文件，以免被临时文件污染
    if os.path.exists(cpp_path+".autocompilation"):
        # logger.info("  Restore from .autocompilation file: {}".format(cpp_path+".autocompilation"))
        os.system("cp {} {}".format(
            cpp_path+".autocompilation", cpp_path))

    if scan_and_modity_for_ontransact(cpp_path):
        FoundOnTransactFunction = True
        logger.info("  Source File: {}".format(cpp_path))
        # 2.找到cpp文件所在目录的编译文件，可以是mk文件或者bp文件
        # 注意默认cpp和编译文件在同一目录 TODO 是否有例外情况？

        # 删除历史lib和bin，以免被遗留文件污染
        lib64_outputdir = os.path.join(output_dir, "lib64")
        bin_outputdir = os.path.join(output_dir, "bin")
        os.system("rm -rf {}".format(lib64_outputdir))
        os.system("rm -rf {}".format(bin_outputdir))

        cpp_path_dir = os.path.dirname(cpp_path)

        find_compilation_in_current_folder = False
        FoundCompilationFile = False

        for file in os.listdir(cpp_path_dir):
            if file == "Android.bp":
                if os.path.exists(os.path.join(cpp_path_dir, file+".autocompilation")):
                    # logger.info("  Restore from .autocompilation file: {}".format(os.path.join(cpp_path_dir,file+".autocompilation")))
                    os.system("cp {} {}".format(os.path.join(
                        cpp_path_dir, file+".autocompilation"), os.path.join(cpp_path_dir, file)))
                FoundCompilationFile = True
                find_compilation_in_current_folder = True
                compilation_file_path = os.path.join(
                    cpp_path_dir, file)
                section_names, defaults_in = parser_bp_file(
                    os.path.basename(cpp_path), compilation_file_path)

                if is_historical_compiled(section_names, historical_compiled_targets):
                    logger.info(
                        "  Target has already been compiled and generate target file in local folder {}".format(compilation_file_path))
                    # restore the orinal bp file
                    os.system("cp {}.autocompilation {}".format(
                        compilation_file_path, compilation_file_path))
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(
                        cpp_path, cpp_path))
                    break

                # failed targets when compilation
                global compiled_targets
                if os.path.join(cpp_path_dir, file) in compiled_targets:
                    logger.info(
                        "  Target has already been compiled and failed {}".format(compilation_file_path))
                    # restore the orinal bp file
                    os.system("cp {}.autocompilation {}".format(
                        compilation_file_path, compilation_file_path))
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(
                        cpp_path, cpp_path))
                    break

                build_new_bp_file(section_names, os.path.join(
                    cpp_path_dir, file), defaults_in)

            elif file == "Android.mk":
                FoundCompilationFile = True
                find_compilation_in_current_folder = True
                if os.path.exists(os.path.join(cpp_path_dir, file+".autocompilation")):
                    # logger.info("  Restore from .autocompilation file: {}".format(os.path.join(cpp_path_dir,file+".autocompilation")))
                    os.system("cp {} {}".format(os.path.join(
                        cpp_path_dir, file+".autocompilation"), os.path.join(cpp_path_dir, file)))
                section_names = build_new_mk_file(
                    os.path.join(cpp_path_dir, file))

                if is_historical_compiled(section_names, historical_compiled_targets):
                    compilation_file_path=os.path.join(cpp_path_dir, file)
                    logger.info(
                        "  Target has already been compiled and generate target file in local folder {}".format(compilation_file_path))
                    # restore the orinal bp file
                    os.system("cp {}.autocompilation {}".format(
                        compilation_file_path, compilation_file_path))
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(
                        cpp_path, cpp_path))
                    break

            if FoundCompilationFile:

                compilation_file_path = os.path.join(
                    cpp_path_dir, file)

                logger.info(
                    "  Compilation file: {}".format(compilation_file_path))
                
                # if target is in black list: we know it does not need to be compiled
                if is_in_compilation_black_list(compilation_file_path):
                    # restore the orinal bp file
                    os.system("cp {}.autocompilation {}".format(
                        compilation_file_path, compilation_file_path))
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(
                        cpp_path, cpp_path))
                    break

                extract_transaction_code={"extract":True,"cpp_file_name":os.path.basename(cpp_path)}
                build_output = compile_target(os.path.join(cpp_path_dir, file),extract_transaction_code)
                if b"build completed successfully" in build_output:
                    logger.info("  Build Successful")
                else:
                    logger.info("Build Failed")
                    logger.info("{}".format(
                        compilation_file_path))
                    # restore the orinal bp file
                    os.system("cp {}.autocompilation {}".format(
                        compilation_file_path, compilation_file_path))
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(
                        cpp_path, cpp_path))
                    # failed targets
                    compiled_targets.append(
                        os.path.join(cpp_path_dir, file))
                    break

                # restore the orinal bp file
                os.system("cp {}.autocompilation {}".format(
                    compilation_file_path, compilation_file_path))
                # restore the orinal cpp file
                os.system("cp {}.autocompilation {}".format(
                    cpp_path, cpp_path))

                logger.info("  Finding the correct target file ")
                # In general, section names have the correct the building target
                for target in section_names:
                    # is a library
                    if target.startswith("lib"):
                        lib64_outputdir = os.path.join(
                            output_dir, "lib64")
                        if not os.path.exists(lib64_outputdir):
                            continue
                        libs = os.listdir(lib64_outputdir)
                        if target+".so" in libs:
                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets")):
                                os.mkdir(os.path.join(
                                    current_autocompile_py_path, "Targets"))
                            if os.path.exists(os.path.join(current_autocompile_py_path, "Targets", target)):
                                os.system(
                                    "rm -rf {}".format(os.path.join(current_autocompile_py_path, "Targets", target)))

                            os.mkdir(os.path.join(
                                current_autocompile_py_path, "Targets", target))
                            libpath = os.path.join(
                                lib64_outputdir, target)
                            target_path = os.path.join(
                                current_autocompile_py_path, "Targets", target)
                            
                            logger.warning("Found the target, will copy the target from {}".format(libpath+".so"))
                            logger.warning("Will Patch .so file {} with patcher ".format(libpath+".so"))
                            # Patch trace_pc_guard function in target.so file  (note that we only need to patch so file, for executable, we dont)
                            patch_target_offset, real_trace_pc_guard_offset =  extract_instruction_bytecode(libpath+".so")
                            patch_elf(patch_target_offset, real_trace_pc_guard_offset,libpath+".so")

                            os.system("cp {} {}".format(libpath+".so", target_path))
                            
                            # Try to locate the service
                            locate_service(os.path.join(target_path,os.path.basename(libpath+".so")),local_target_path=target_path,fuzz_duration=fuzz_duration)

                    # is an executable
                    else:
                        bin_outputdir = os.path.join(
                            output_dir, "bin")
                        if not os.path.exists(bin_outputdir):
                            continue
                        bins = os.listdir(bin_outputdir)
                        if target in bins:
                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets")):
                                os.mkdir(os.path.join(
                                    current_autocompile_py_path, "Targets"))
                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets", target)):
                                os.mkdir(os.path.join(
                                    current_autocompile_py_path, "Targets", target))
                                binpath = os.path.join(
                                    bin_outputdir, target)
                                logger.info(
                                    "Found the target, will copy the target from {}".format(binpath))
                                target_path = os.path.join(
                                    current_autocompile_py_path, "Targets", target)
                                os.system("cp {} {}".format(
                                    binpath, target_path))
                                locate_service(os.path.join(target_path,os.path.basename(binpath)),local_target_path=target_path,fuzz_duration=fuzz_duration)
                break

        if not find_compilation_in_current_folder:
            logger.info(
                "  Does not find compilation file in the folder of cpp")

    
    return FoundCompilationFile, FoundOnTransactFunction

def compile_entry(fuzz_duration=300):
    """
    find onTransact function implementation
    """
    read_historical_targets()
    global historical_compiled_targets

    for root, dirs, files in os.walk(root_dir):
        for name in files:
            # except .repo and out folder
            if root.find(os.path.join(root_dir,"out"))>=0 \
            or root.find(os.path.join(root_dir,".repo"))>=0\
            or root.find(os.path.join(root_dir,"prebuilts"))>=0:
                continue
            if name.endswith(".cpp") :
                cpp_path = os.path.join(root, name)

                # history support
                cpp_in_history = False
                for bl in cpp_file_history:
                    if bl.strip() in cpp_path:
                        cpp_in_history = True
                        break
                if cpp_in_history:
                    logger.info(" {} has been compiled before".format(cpp_path))
                    continue

                # 排除out目录
                if cpp_path.find(os.path.join(root_dir, "out")) >= 0 or \
                    cpp_path.find("framework-fuzz") > 0 or \
                        cpp_path.find("tests/") > 0:
                    # or \
                    #     cpp_path.find("ISimpleperfService.cpp")<0:
                    continue
                FoundCompilationFile = False
                FoundOnTransactFunction = False
                FoundCompilationFile, FoundOnTransactFunction = process_one_target(
                    cpp_path,fuzz_duration=fuzz_duration)
                if not FoundOnTransactFunction:
                    continue
                # 该文件有onTransact函数实现，则将当前文件写入文件保存历史
                with open(os.path.join(current_autocompile_py_path,"cpp_history.txt"),'a+') as f:
                    f.write(cpp_path+'\n')


                # 如果在cpp所在目录没有找到编译文件，则递归向上找
                if not FoundCompilationFile:
                    cpp_path_dir = os.path.dirname(os.path.dirname(cpp_path))
                    while not FoundCompilationFile:
                        
                        for file in os.listdir(cpp_path_dir):
                            FoundCompilationFile = False
                            if file == "Android.bp":
                                if os.path.exists(os.path.join(cpp_path_dir, file+".autocompilation")):
                                    # logger.info("  Restore from .autocompilation file: {}".format(os.path.join(cpp_path_dir,file+".autocompilation")))
                                    os.system("cp {} {}".format(os.path.join(
                                        cpp_path_dir, file+".autocompilation"), os.path.join(cpp_path_dir, file)))
                                FoundCompilationFile = True
                                find_compilation_in_current_folder = True
                                compilation_file_path = os.path.join(
                                    cpp_path_dir, file)
                                section_names, defaults_in = parser_bp_file(
                                    name, compilation_file_path)

                                if is_historical_compiled(section_names, historical_compiled_targets):
                                    logger.info(
                                        "  Target has already been compiled and generate target file in local folder {}".format(compilation_file_path))
                                    # restore the orinal bp file
                                    os.system("cp {}.autocompilation {}".format(
                                        compilation_file_path, compilation_file_path))
                                    # restore the orinal cpp file
                                    os.system("cp {}.autocompilation {}".format(
                                        cpp_path, cpp_path))
                                    break

                                # failed targets when compilation
                                global compiled_targets
                                if os.path.join(cpp_path_dir, file) in compiled_targets:
                                    logger.info(
                                        "  Target has already been compiled and failed {}".format(compilation_file_path))
                                    # restore the orinal bp file
                                    os.system("cp {}.autocompilation {}".format(
                                        compilation_file_path, compilation_file_path))
                                    # restore the orinal cpp file
                                    os.system("cp {}.autocompilation {}".format(
                                        cpp_path, cpp_path))
                                    break

                                build_new_bp_file(section_names, os.path.join(
                                    cpp_path_dir, file), defaults_in)

                            elif file == "Android.mk":
                                FoundCompilationFile = True
                                if os.path.exists(os.path.join(cpp_path_dir, file+".autocompilation")):
                                    # logger.info("  Restore from .autocompilation file: {}".format(os.path.join(cpp_path_dir,file+".autocompilation")))
                                    os.system("cp {} {}".format(os.path.join(
                                        cpp_path_dir, file+".autocompilation"), os.path.join(cpp_path_dir, file)))

                                section_names = build_new_mk_file(
                                    os.path.join(cpp_path_dir, file))
                                compilation_file_path = os.path.join(
                                    cpp_path_dir, file)
                                if is_historical_compiled(section_names, historical_compiled_targets):
                                    logger.info(
                                        "  Target has already been compiled and generate target file in local folder {}".format(compilation_file_path))
                                    # restore the orinal bp file
                                    os.system("cp {}.autocompilation {}".format(
                                        compilation_file_path, compilation_file_path))
                                    # restore the orinal cpp file
                                    os.system("cp {}.autocompilation {}".format(
                                        cpp_path, cpp_path))
                                    break

                            if FoundCompilationFile:

                                compilation_file_path = os.path.join(
                                    cpp_path_dir, file)

                                logger.info(
                                    "  Compilation file: {}".format(compilation_file_path))
                                # if target is in black list: we know it does not need to be compiled
                                if is_in_compilation_black_list(compilation_file_path):
                                    # restore the orinal bp file
                                    os.system("cp {}.autocompilation {}".format(
                                        compilation_file_path, compilation_file_path))
                                    # restore the orinal cpp file
                                    os.system("cp {}.autocompilation {}".format(
                                        cpp_path, cpp_path))
                                    break
                                
                                extract_transaction_code={"extract":True,"cpp_file_name":os.path.basename(cpp_path)}
                                build_output = compile_target(
                                    os.path.join(cpp_path_dir, file),extract_transaction_code)
                                if b"build completed successfully" in build_output:
                                    logger.info("  Build Successful")
                                else:
                                    logger.info("Build Failed")
                                    logger.info("{}".format(
                                        compilation_file_path))
                                    # restore the orinal bp file
                                    os.system("cp {}.autocompilation {}".format(
                                        compilation_file_path, compilation_file_path))
                                    # restore the orinal cpp file
                                    os.system("cp {}.autocompilation {}".format(
                                        cpp_path, cpp_path))
                                    # failed targets
                                    compiled_targets.append(
                                        os.path.join(cpp_path_dir, file))
                                    break

                                # restore the orinal bp file
                                os.system("cp {}.autocompilation {}".format(
                                    compilation_file_path, compilation_file_path))
                                # restore the orinal cpp file
                                os.system("cp {}.autocompilation {}".format(
                                    cpp_path, cpp_path))

                                logger.info(
                                    "  Finding the correct target file ")
                                # In general, section names have the correct the building target
                                for target in section_names:
                                    # is a library
                                    if target.startswith("lib"):
                                        lib64_outputdir = os.path.join(
                                            output_dir, "lib64")
                                        if not os.path.exists(lib64_outputdir):
                                            continue
                                        libs = os.listdir(lib64_outputdir)
                                        if target+".so" in libs:
                                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets")):
                                                os.mkdir(os.path.join(
                                                    current_autocompile_py_path, "Targets"))
                                            if os.path.exists(os.path.join(current_autocompile_py_path, "Targets", target)):
                                                os.system(
                                                    "rm -rf {}".format(os.path.join(current_autocompile_py_path, "Targets", target)))

                                            os.mkdir(os.path.join(
                                                current_autocompile_py_path, "Targets", target))
                                            libpath = os.path.join(
                                                lib64_outputdir, target)
                                            target_path = os.path.join(
                                                current_autocompile_py_path, "Targets", target)
                                            
                                            logger.warning("Found the target, will copy the target from {}".format(
                                                libpath+".so"))
                                            # Patch trace_pc_guard function in target.so file  (note that we only need to patch so file, for executable, we dont)
                                            logger.warning("Will Patch .so file {} with patcher ".format(libpath+".so"))
                                            patch_target_offset, real_trace_pc_guard_offset =  extract_instruction_bytecode(libpath+".so")
                                            patch_elf(patch_target_offset, real_trace_pc_guard_offset,libpath+".so")
                                            os.system("cp {} {}".format(
                                                libpath+".so", target_path))
                                            # Try to locate the service
                                            locate_service(os.path.join(target_path,os.path.basename(libpath+".so")),local_target_path=target_path,fuzz_duration=fuzz_duration)

                                    # is an executable
                                    else:
                                        bin_outputdir = os.path.join(
                                            output_dir, "bin")
                                        if not os.path.exists(bin_outputdir):
                                            continue
                                        bins = os.listdir(bin_outputdir)
                                        if target in bins:
                                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets")):
                                                os.mkdir(os.path.join(
                                                    current_autocompile_py_path, "Targets"))
                                            if not os.path.exists(os.path.join(current_autocompile_py_path, "Targets", target)):
                                                os.mkdir(os.path.join(
                                                    current_autocompile_py_path, "Targets", target))
                                                binpath = os.path.join(
                                                    bin_outputdir, target)
                                                logger.info(
                                                    "Found the target, will copy the target from {}".format(binpath))
                                                target_path = os.path.join(
                                                    current_autocompile_py_path, "Targets", target)
                                                os.system("cp {} {}".format(
                                                    binpath, target_path))
                                                locate_service(os.path.join(target_path,os.path.basename(binpath)),local_target_path=target_path,fuzz_duration=fuzz_duration)
                                break

                        if not FoundCompilationFile:   
                            cpp_path_dir = os.path.dirname(cpp_path_dir)
                    # restore the orinal cpp file
                    os.system("cp {}.autocompilation {}".format(cpp_path, cpp_path))

def locate_transaction_code(cpp_path,first_case_str):
    """Given a cpp path, find its transaction code in onTransaction function
    TODO：This function is NASTY CODE! please use clang to parse it, based on pass

    Args:
        cpp_path ([str]): [description]
        first_case_str ([str]): [description]
    """
    cpp_path = os.path.dirname(cpp_path)
    global first_transaction_code
    global last_transaction_code


    Found_Value = False

    # maxmium depth to find is 3 
    max_deepth = 3

    # 有可能这个值本身就是一个数值，如果是的话就尝试一下eval，然后返回
    try:
        first_transaction_code = eval(first_case_str.strip())
        last_transaction_code = first_transaction_code + 100
        return 
    except:
        pass
    
    while not Found_Value and max_deepth > 0: 
        for root, dirs, files in os.walk(cpp_path):
            for name in files:
                file_path = os.path.join(root,name)
                if not os.path.isdir(file_path) and not os.path.islink(file_path):
                    with open(file_path,"r",errors="ignore") as f:
                        content = f.read()
                    case_pattern = re.compile(first_case_str+"\s*=(.*)")
                    matches = case_pattern.findall(content)
                    if len(matches)>0:
                        Found_Value = True
                        first_transaction_code = matches[0].strip().replace(",","")
                        first_transaction_code = first_transaction_code.replace("android::IBinder::FIRST_CALL_TRANSACTION","1")
                        first_transaction_code = first_transaction_code.replace("IBinder::FIRST_CALL_TRANSACTION","1")
                        
                        
                        try:
                            first_transaction_code = eval(first_transaction_code)
                            # we locate the first transaction code successfully, will locate last code
                            case_pattern2 = re.compile(first_case_str+"\s*=.*")
                            matche2 = case_pattern2.findall(content)
                            if len(matche2)>=0:
                                line_content = matche2[0]
                            tmp_last_code =0
                            start_count = False
                            for line in content.split("\n"):
                                if line.find(line_content)>=0:
                                    tmp_last_code+=1
                                    start_count=True
                                if start_count and line.find("}")>=0:
                                    break
                                if start_count:
                                    tmp_last_code+=1
                            if tmp_last_code!=0:
                                last_transaction_code = first_transaction_code + tmp_last_code
                            else:
                                last_transaction_code = first_transaction_code + 400


                        except:
                            logger.info("exception first_transaction_code {}".format(first_transaction_code))
                            first_transaction_code = 1
                            last_transaction_code = 65535


                        logger.warning("Find first value {} in {}".format(first_transaction_code,file_path))
                        return 

        cpp_path = os.path.dirname(cpp_path)
        logger.info(cpp_path)
        max_deepth-=1
        if cpp_path == root_dir:
            logger.warning("Does not find first value")
            first_transaction_code = 1
            return

def compile_essentials():
    """
    Compile targets like afl-fuzz afl-showmap and android-wp-manager,
    then copy these targets to ../fuzz_daemon/ folder
    """
    logger.info("Building essential binaries like afl-fuzz and android-wp-manager")
    bp_file_path = os.path.join(current_autocompile_py_path,"..","..","Android.bp")
    build_output = compile_target(bp_file_path)
    if b"build completed successfully" in build_output:
        logger.info("Essentials binaries built success")
    # copy essential binaries to ../fuzz_daemon folder
    afl_path=os.path.join(output_dir,"bin","afl-fuzz")
    manager_path=os.path.join(output_dir,"bin","android-wp-manager")
    fuzz_daemon_path = os.path.join(current_autocompile_py_path,"..","fuzz_daemon")
    logger.info("Copy afl-fuzz to fuzz_daemon")
    cmd = "cp {} {}".format(afl_path,fuzz_daemon_path)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    logger.info("Copy android-wp-manager to fuzz_daemon")
    cmd = "cp {} {}".format(manager_path,fuzz_daemon_path)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    output = proc.communicate()
    

if __name__ == "__main__":
    # retore raw binary files to the phone incase of unexpected break
    restore_raw()
    # compile essential binaries like afl-fuzz android-wp-manager and others
    # copy essential binaries to ../fuzz_daemon folder
    compile_essentials()
    

    # restore .autocompile fils incase of unexpected break
    restore_autocompilation_files()
    # compile targets and fuzz 
    compile_entry(fuzz_duration=7200)
    
    # # for debug
    # locate_service('/media/puzzor/hms/aosp/external/framework-fuzz/tools/auto_compilation/Targets/surfaceflinger/surfaceflinger',
    #                 '/media/puzzor/hms/aosp/external/framework-fuzz/tools/auto_compilation/Targets/surfaceflinger',fuzz_duration=120)