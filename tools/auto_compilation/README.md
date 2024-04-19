用于自动编译带有onTransact函数实现的目标，编译同时会添加ASAN以及AFL所必须的插桩代码。编译完成后会在当前脚本所在目录生成Targets文件夹，里面包含了编译好的目标，替换掉设备上的目标即可Fuzz

使用方法： 
0.安装依赖 requirements.txt
1.根据实际环境修改脚本中的 output_dir 和 lunch_cmd 参数
2.切换到当前目录运行 python auto_compilation.py等待编译完成即可


分析过程中需要识别 transaction code，而这个code并非仅仅在该服务的header文件中进行了定义。例如对于aosp/frameworks/native/libs/graphicsenv/IGpuService.cpp的ontransact函数来说，其case值包含了一个SHELL_COMMAND_TRANSACTION，而这个value在其他地方才进行的定义。

如果出现了类似于 call void@__sanitizer_cov_trace_pc_guard ***** inlinable function call类似的错误，可以尝试添加
sanitize:{
misc_undefined:["bounds"]
}
选项