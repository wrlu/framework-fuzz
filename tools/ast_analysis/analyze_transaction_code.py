#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   test.py
@Time    :   2022/09/16
@Author  :   @Puzzor 
@Version :   1.0
@Contact :   puzzorsj@gmail.com
@Desc    :   遍历由llvm生成的AST，并通过AST分析出其中onTransact函数中的case值
'''

# here put the import lib
import json
import pdb
import sys
import os

current_analysis_py_path = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(current_analysis_py_path,"..","utils"))
from custom_logger import logger

global transaction_dict

transaction_dict={}


def dict_generator(indict, pre=None,function_name=""):
    """iterate the AST dict passed in, and find the case value in onTransact function

    Args:
        indict ([type]): [description]
        pre ([type], optional): [description]. Defaults to None.
        function_name (str, optional): [description]. Defaults to "".

    Yields:
        [type]: [description]
    """
    global transaction_dict
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                if len(value) == 0:
                    yield pre+[key, '{}']
                else:
                    # 只有在遇到新函数的时候才更新函数名这个参数
                    if "kind" in value and value['kind']=="CXXMethodDecl" and "name" in value:
                        for d in dict_generator(value, pre + [key],value["name"]):
                                yield d
                    else:
                        # 沿用旧函数名
                        for d in dict_generator(value, pre + [key],function_name):
                            yield d
            elif isinstance(value, list):
                if len(value) == 0:                   
                    yield pre+[key, '[]']
                else:
                    for v in value:
                        # 只有在遇到新函数的时候才更新函数名这个参数
                        if "kind" in v and v['kind']=="CXXMethodDecl" and "name" in v:
                            for d in dict_generator(v, pre + [key],v["name"]):
                                yield d
                        else:
                            # 沿用旧函数名
                            for d in dict_generator(v, pre + [key],function_name):
                                yield d
            elif isinstance(value, tuple):
                if len(value) == 0:
                    yield pre+[key, '()']
                else:
                    for v in value:
                        # 只有在遇到新函数的时候才更新函数名这个参数
                        if "kind" in v and v['kind']=="CXXMethodDecl" and "name" in v:
                            for d in dict_generator(v, pre + [key],v["name"]):
                                yield d
                        else:
                            # 沿用旧函数名
                            for d in dict_generator(v, pre + [key]):
                                yield d
            else:
                # 如果是onTransact函数中的CaseStmt，则找出其数值 
                if function_name=="onTransact":
                    if key =="kind" and value == "CaseStmt":
                        # logger.info("Found Case Statement in onTransact")
                        try:
                            case_name = indict['inner'][0]['inner'][0]['inner'][0]['referencedDecl']['name']
                        except:
                            case_name = "UNKNOWN"
                            # pdb.set_trace()

                        case_value = indict['inner'][0]['value']
                        transaction_dict[case_name] = case_value
                        logger.info("{} : {}".format(case_name, case_value))   
                yield pre + [key, value]
    else:
        yield indict


#0. 首先需要利用 llvm 生成目标 cpp 的 AST, 在 -c选项之后添加如下参数，生成json格式的AST树（会输出到stdout）：
# -fsyntax-only -Xclang -ast-dump=json

#1. 将步骤0的输出重定向到一个json文件中

#2. 调用此脚本对json文件进行分析，得到case value
# logger.info("Openning the AST file")
# content =open("sampleast.json","r").read()
# logger.info("Loading the content to a json object")
# ast_json = json.loads(content)

# logger.info("Parsing the AST")
# for i in dict_generator(ast_json):
#     pass
        

