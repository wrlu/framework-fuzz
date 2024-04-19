# 多节点Fuzz群控工具

## 简介
工具用于对多个手机节点Fuzz的群控功能，包括控制Fuzz启动、监控Fuzz节点异常等功能

## 依赖
1. 根据requirements.txt 安装依赖  pip install -r requirements.txt
2. adb工具
3. 手机root权限

## 使用方法
1. 首先需要framework-fuzz根目录下的README编译目标模块(.so 或者 ELF)
2. 在fuzz_daemon目录下创建以目标模块（不包含扩展名）为名的文件夹。例如如果目标模块是libsyssvccallrecordservice.so，则创建libsyssvccallrecordservice文件夹（注意文件夹名称要和不包含扩展名的目标模块的名称一致）。在文件夹下拷贝编译好的目标模块（libsyssvccallrecordservice.so)和config.prop(该文件参考根目录下的说明进行构建)
3. 在步骤2创建的文件夹下构建AFL所需要的in目录，其中存放初始的测试种子
4. 在daemon.py脚本中修改`target_file`变量为目标文件夹的名称（注意不包含扩展名）
5. 在daemon.py脚本中修改 `transaction_start` 和 `transaction_start` 两个变量为目标模块所接受的transaction code的范围
6. 由于在进行binder fuzz过程中可能会出现binder服务异常，或者目标程序退出等异常行为，因此需要定期监控目标设备中的状态是否正常。因此可能需要根据实际情况对daemon.py 中的 check_status函数进行修改
6. 运行daemon.py即可 python daemon.py (注意运行环境尽量在linux下，在windows下运行时可能会出现部分路径os.path.join函数异常)

## 案例
在此介绍一个对gatekeeperd服务的Fuzz完整流程。
gatekeeperd所对应的服务名称（SERVICE_NAME）为android.service.gatekeeper.IGateKeeperService，而interface token为android.service.gatekeeper.IGateKeeperService (可通过 service list |grep -i gatekeeperd 查看到)。

### 准备工作及编译
首先定位到gatekeeperd服务的onTransact函数（IGateKeeperService.cpp中：适用于hmos源码，aosp可能不适用，请具体确认），在该cpp中添加头文件 #include"service/WpService.h"，同时在onTransact函数中添加WpService的调用部分，以及修改Android.bp（参见根目录README.md#add-code-to-target-service-for-coverage-support部分）。
`注意：为了完整跑通并调试，需要在onTransact函数的入口处添加一句 ALOGE("[FUZZ_TARGET::onTransact] Transaction code %x",code);此句可帮助后续利用logcat进行观察调试` 
之后切换到该模块(gatekeeperd)的目录，设置好source(srouce $AOSP$/build/envsetup.sh)，以及lunch 之后，利用mm进行编译。编译完成后应该在$AOSP$/out目录生成一个gatekeeperd的程序。

### 拷贝到目标设备
编译完成android-wp-manager（参考framework-fuzz根目录的README.md#compile-wrapper）和gatekeeperd程序后，将gatekeeperd拷贝到目标机器中(
 1. adb root && adb remount && adb push gatekeeperd /data/local/tmp/ 
 2. adb shell "pkill gatekeeperd && cp /data/local/tmp/gatekeeperd /system/bin/ ")

### 准备测试样本和配置文件
#### 测试样本准备
注意到onTransact函数中共可以接受的transaction code的有效范围是0-5，因此需要准备6个种子文件，文件的格式按照如下结构进行组织：

```
struct{
    int transaction code; (4字节)
    char* data; (长度不固定)
}
```
注意这个struct结构是根据android-wp-manager中的代码来定义的，android-wp-manager会将种子文件的前四个字节解析为transaction code,而将后面的部分解析为Parcel的Data。
例如对于code为0-2的种子可以分别准备成
```\x00\x00\x00\x00AAAAAAAAA```
```\x01\x00\x00\x00AAAABBAAAAA```
```\x02\x00\x00\x00AADEAAAAAAADC```
将6个种子文件命名为0.bin - 5.bin之后拷贝到目标设备中（例如可以是/data/local/tmp/）

#### 配置文件准备
android-wp-manager需要一个配置文件（例如config.prop）作为第一个参数传入。
config.prop中的两个关键参数为SERVICE_NAME和INTERFACE_TOKEN，一个合法的文件样例如下
```
SERVICE_NAME:android.service.gatekeeper.IGateKeeperService
INTERFACE_TOKEN:android.service.gatekeeper.IGateKeeperService
SERVICE_FIRST_CALL:0
SERVICE_LAST_CALL:1000
IS_SA:0
```
注意SERVICE_FIRST_CALL，SERVICE_LAST_CALL可以随便写（这两部分目前已经没有作用了，随便给值不影响），IS_SA设置为0。另外注意保存成config.prop一定要检查其中的换行为\n而不是\r\n，否则可能会影响解析（android-wp-manager中的解析代码写的不完善，注意一下即可）。

准备好配置文件后拷贝到目标设备上(/data/local/tmp/)即可。

### 运行并观察
在这一阶段将利用logcat和coverage_calculator模块(在framework-fuzz/tools目录下)对运行过程和代码覆盖进行观察（注意观察分为两部分：logcat和代码覆盖）。
#### 运行
1. 新开一个adb shell，将framework-fuzz/tools/coverage_calculator/frida-server-15.2.2-android-arm64.huawei拷贝到/data/local/tmp/中，并chmod +x，之后在设备上执行setenforce 0 并运行该程序(详细可参考framework-fuzz/tools/coverage_calculator/README.md)
2. 新开一个host的shell，切换到framework-fuzz/tools/coverage_calculator/目录，并参考framework-fuzz/tools/coverage_calculator/README.md，运行strace.py (`python sktrace.py -m attach -l gatekeeperd -i 0x7e3c gatekeeperd`)。注意偏移请参考文档进行定位。运行脚本后应该可以输出类似如下信息：
```
libname:gatekeeperd
libbase:0x64291cc000
```
至此代码覆盖的记录准备工作完成。
3. 接下来新开一个 adb shell, 执行 `logcat -c && logcat |grep FUZZ_TARGET`，准备观察logcat中的输出
4. 新开一个adb shell，切换到 /data/local/tmp/目录下，执行android-wp-manager来处理6个样本文件(0.bin -5.bin)
```
./android-wp-manager .config.prop 0.bin
./android-wp-manager .config.prop 1.bin
...
./android-wp-manager .config.prop 5.bin
```
注意每处理一个样本文件之后都应该观察到logcat中的输出，以及代码覆盖的输出，都正确的情况下，应该观察到logcat中的如下信息
```
[FUZZ_TARGET::onTransact] Transaction code 0
[FUZZ_TARGET::onTransact] Transaction code 1
...
[FUZZ_TARGET::onTransact] Transaction code 6
```
以及代码覆盖窗口中的类似如下输出：
```
...
gatekeeperd+0x83b8
gatekeeperd+0x83bc
...
```

5. 待5个样本文件都解析完成后，在代码覆盖记录窗口按下回车或者ctrl+c结束代码覆盖的记录。之后在strace.py所在目录下应该生成一个cov.log文件，记录了代码覆盖的详细信息。将此文件，以及重新编译的gatekeeperd程序拷贝出来，利用IDA Pro和Lighthouse插件进行可视化。正确情况下应该可能够在IDA中观察到Ontransact函数中的不同swtich分支被覆盖到。
```
switch(code){
    case 0:
    case 1:
    ...
    case 5:
    default:
}
```
至此可以确认程序运行正常。


### TODO
变异数据时候需要对fd进行重点变异，data中存放了一个fd，fd对应存放了文件内容。

fuzz 过程中的代码覆盖率干扰问题：
假设目标服务中的OnTransact函数会被系统自己所经常调用，此时如果利用afl进行fuzz的过程中就会存在系统自己调用的时候也会产生额外的代码覆盖，进而造成代码覆盖被干扰的情况。
一种思路是对llvm的__sanitizer_cov_trace_pc_guard函数进行重新定义，加一个标志位，以便只在特定情况下才trace？