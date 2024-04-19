此目录用于编译一个demo服务，该服务可以用于被fuzz测试，分别进入不同子目录然后mm即可编译。编译完成后将程序和库文件拷贝到手机的lib和bin目录下即可，拷贝后运行程序
如果编译报错，则可能需要在frameworks/native/libs/binder/include/binder/IInterface.h手动添加服务的白名单:
在constexpr const char* const kManualInterfaces[] 中添加 "android.rex.IRexPlayerService",


## Fuzzer验证步骤

1. 编译 demoTargetService/librexservice 和 demoTargetService/rexserver之后会生成 rexplayerserver 和librexservice.so文件

2. 运行 framework-fuzz/tools/trace_pc_guard_patcher/patcher.py 文件对 librexservice.so 打patch: python patcher.py /media/hms/aosp/out/target/product/generic_arm64/system/lib64/librexplayerservice.so (patch后会覆盖原有文件)

3. 将两个文件分别拷贝到 /system/bin/ 和 /system/lib64/目录

4. 在shell中运行 rexplayerserver 启动编译好的native服务

5. 拷贝demoTargetService目录下的config.prop到手机上

6. 拷贝编译好的 afl-fuzz 和 android-wp-manager 到手机上，和config.prop在同一目录

7. 准备一个初始种子，在手机上建立一个in目录，并在目录中创建一个seed.bin文件，文件内容任意，但长度最好大于10个字节，例如可以是 "AAAAAAAAAAAAAAAAAAA"。样例文件可以参见demoTargetService/librexservice/seeds/目录

8. 运行命令： ./afl-fuzz -i in/ -o out/ -s 0 -e 6  -m none -- ./android-wp-manager ./config.prop @@ 
   注意-s要给transaction code的最小值，-e 要给最大值(0和6可以参见demoTargetService/IRexPlayerService.cpp中的CODE1-CODE6)

运行完上述命令后，注意观察AFL的path数量，正常情况下，在一段时间（10分钟左右，时间不一定）后，path的数量应该能够到达9。到达9个path之后可以手工检查9个文件的内容应该包含了5个code，以及3个code为1的情况下的不同data值（1,2,other），和一个初始种子。
至此说明fuzz正常，可以对其他系统服务进行fuzz。


## 分析路径覆盖反馈不正确的问题
### 问题1描述
在测试过程中经常会出现明明不同的Transaction Code触发了多条路径分支，但是Fuzzer并没有显示有新的路径的情况。具体现象为：通过logcat可以发现不同transaction code 分支被触发，但是afl没有发现新路径的情况。

### 问题分析
有以下几种可能的情况
1. 目标没有被插桩上。 虽然在编译选项中指定了trace_pc_guard，但是实际编译完的目标程序没有被插桩成功，且编译过程中并无报错。这是由于一些编译选项冲突造成的，需要手工单独分析
2. 在AFL一开始的运行过程中，会执行 perform_dry_run ，而在perform_dry_run中会继续执行calibrate_case -> write_to_testcase, 而我们在 write_to_testcase 函数中增加了对transaction code 的随机化选择部分，因此会造成在 perform_dry_run 的过程中就遍历了很多transaction code，导致分支被触发，从而引发后续在fuzz过程中无法识别到新的路径覆盖分支。经分析后确实由此原因造成，因此对 write_to_testcase 进行了修改，在 perform_dry_run 中的调用流程过程中，在 write_to_testcase 不会对 transaction code 进行随机

### 问题2描述
如果目标是个.so，当加载这个so文件的主进程没有使用 android-wp-service-external-defaults 编译时，即便so文件被 trace_pc_guard 编译了，也无法准确的记录路径覆盖

### 问题复现及分析
不加 android-wp-service-external-defaults 选项编译 rexplayerserver，之后构建6个种子文件，每个种子文件中的前4个字节设置为不同的transaction code:X (1-6)。
利用 afl-showmap 观察不同种子文件对应的bitmap
./afl-showmap -o rex_notracepc_showmap/X.map -t 1000 -m none -- ./android-wp-manager ./conf.prop X.bin
运行过程中可以使用logcat观察是否触发了不同的transaction code: logcat |grep "BnInterface: onTransact, code"

过程中应该观察到不同的 transaction code 被触发，且记录完成之后观察1.map 到 6.map，可以发现几乎所有的map都一样。说明虽然不同的路径被触发了，但是最终的map却是一致的。

### 深入调试分析
从 afl-showmap 的输出可以发现有可能是 __afl_area_ptr 未能记录到共享内存中(ashmem)并反馈给 android-wp-manager 。尝试以下调试方案：

a. 在 onTransact 开始处对 __afl_area_ptr[0]=123; 之后在 WpManager::call 中观察 __afl_area_ptr[0] 的数值。
经过分析后发现两处的__afl_area_ptr[0]值是一致的，也就是说可能并非由于共享内存(ashmem)的问题引发。

b. 在调试a的过程中偶然发现，编译好的库中的trace_pc_guard没有被调用。具体情况为，单独将库函数重新编译，并将 trace_pc_guard 函数中插入一个LOG函数进行输出，而载入其的binary只做普通的插桩，之后发现bitmap在不同code下是不同的，而通过logcat却没有发现有插入的LOG的输出。
之后进一步将binary中的插桩删除，即不用 android-wp-service-external-defaults 编译，而库函数正常的使用LOG在 trace_pc_guard 中进行插桩输出， 之后运行发现竟然没有 LOG 的输出，也就是这个 trace_pc_guard 虽然被编译进去了，但是没有被触发。

具体情况为：每一个真正的 __sanitizer_cov_trace_pc_guard 调用被编译器编译后，会有一个 ".__sanitizer_cov_trace_pc_guard" 类似的wrapper函数(注意有个前面有个点)调用过程如下：

android::BnRexPlayerService::onTransact:
   -> BL              .__sanitizer_cov_trace_pc_guard
   .__sanitizer_cov_trace_pc_guard :
      -> ADRP            X16, #off_96B8@PAGE
      -> LDR             X17, [X16,#off_96B8@PAGEOFF]
      -> ADD             X16, X16, #off_96B8@PAGEOFF
      -> BR              X17
   X17 指向 .got.plt:00000000000096B8 off_96B8        DCQ __sanitizer_cov_trace_pc_guard
   从而进一步调用了真正的 __sanitizer_cov_trace_pc_guard 函数

经过对 ".__sanitizer_cov_trace_pc_guard" 函数增加断点并分析发现，问题出现在此函数中，不知为何在实际运行过程中，此处的X17并不是 指向 __sanitizer_cov_trace_pc_guard。（具体为何不是，以及指向了何处，暂时不知原因）。但是在此基础上的一个解决思路是，将 ".__sanitizer_cov_trace_pc_guard" 中的第一条指令patch为 b __sanitizer_cov_trace_pc_guard 即可（手工验证时候使用了keypatch插件），patch完成后，即便在ELF不使用trace_pc_guard插桩的情况下，so库仍然能够准确的调用 __sanitizer_cov_trace_pc_guard 函数，并记录代码覆盖情况。

缓解措施：
 可以将 .__sanitizer_cov_trace_pc_guard 的第一条指令自动替换为 B __sanitizer_cov_trace_pc_guard



### 问题分析
1.当主进程没有插桩时，so文件的trace_pc_guard的共享内存无法准确记录？


## gdb调试 (注意在使用gdb调试之前，最好能够把aosp整体编译一遍，以便在调试过程中找到一些系统库的符号)

### 观察 librexplayerservice.so 中的插桩是否正常

1. 在host上准备 /media/hms/aosp/aarch64-linux-android-gdb (参考版本：GNU gdb (GDB) 7.9.1.20150607-cvs) https://github.com/Meninblack007/aarch64-linux-android-4.9/blob/master/bin/aarch64-linux-android-gdb
2. 在手机上运行 gdbserver64 :1234 /system/bin/rexplayerserver (1234为端口，96为pid)
3. 
4. 在host上运行 adb forward tcp:1234 tcp:1234 转发端口
5. 在host上运行 aarch64-linux-android-gdb
   a. target remote :1234
   b. file /media/hms/aosp/out/target/product/generic_arm64/system/bin/rexplayerserver
   c. set sysroot /media/hms/aosp/out/target/product/generic_arm64/symbols/
   d. set dir /media/hms/aosp/
   e. set solib-absolute-prefix /media/hms/aosp/out/target/product/generic_arm64/symbols/
   f. set solib-search-path /media/hms/aosp/out/target/product/generic_arm64/symbols/system/lib/
6. 在main函数设置断点，并在库函数的onTransact函数上设置断点
   a. b main
   b. c (继续执行到main函数)
   c. 由于 onTransact 函数很多，这里直接使用源码中的 ontransact 函数所在的行数设置断点：b IRexPlayerService.cpp:50
   d. c (继续执行)
   e. 在手机上运行android-wp-manager 来触发 ontransact 断点 ./android-wp-manager ./config.prop libsensor/in/seed.bin
   f. 运行完步骤e后应该可以触发 ontransact 断点
7. 在 __sanitizer_cov_trace_pc_guard 设置断点
   a. b __sanitizer_cov_trace_pc_guard





### 调试afl-fuzz
1. 在host上准备 aarch64-linux-android-gdb (参考版本：GNU gdb (GDB) 7.9.1.20150607-cvs)
2. 在手机上运行 gdbserver64 :1234 ./afl-fuzz -i libsensor/in/ -o out -s 1 -e 10 -m none -- ./android-wp-manager ./config.prop @@
(注意in目录随便给一下就行，无所谓，config.prop给对了就可以)，config.prop样例如下:
   SERVICE_NAME:rex.player
   INTERFACE_TOKEN:android.rex.IRexPlayerService
   SERVICE_FIRST_CALL:1
   SERVICE_LAST_CALL:10
3. 在host上运行 adb forward tcp:1234 tcp:1234 转发端口
4. 在host上运行aarch64-linux-android-gdb
   a. target remote :1234
   b. file /media/hms/aosp/out/target/product/generic_arm64/system/bin/afl-fuzz
   c. set sysroot /media/hms/aosp/out/target/product/generic_arm64/symbols/