# 种子收集模块

## 概要
此模块用于在目标手机上收集transact函数中的data和code数据，用于作为后续fuzz的种子文件

## 使用方法

0. 手工修改 aosp/frameworks/native/libs/binder/IPCThreadState.cpp 中的transact函数，添加如下代码：

`
#include <fstream>
alog << "******** write to file "<< endl;
std::ofstream outfile("/data/local/tmp/afile.dat",std::ios::app);
alog << data << endl;
outfile << "code: "<<code;
outfile << "\n";
size_t pre_pos = data.dataPosition();
data.setDataPosition(0);
outfile.write( (const char *)data.data(),data.dataSize());
data.setDataPosition(pre_pos);
outfile.flush();
outfile.close();`

此段代码用于hook transact的函数并将其中的data，code保存到文件(/data/local/tmp/afile.dat)中。

1. 编译libbinder.so，并拷贝到和脚本同一目录

2. 运行脚本


在libbluetooth中，上述文件保存的方式可能会失败（暂不知原因），可使用如下代码重定向到logcat中：

std::stringstream ss;
  for(int i=0; i<p_msg->len; ++i)
      ss << std::hex << std::setw(2)<< std::setfill('0') << (int)p_msg->data[i];
  std::string mystr = ss.str();
  LOG(WARNING) <<"BT_HDR_LEN:"<< p_msg->len <<";BT_HDR_DATA:"<< mystr;
