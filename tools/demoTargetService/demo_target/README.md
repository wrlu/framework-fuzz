这个程序用于在android下单独利用afl对单个程序进行测试。

[使用方法]
lunch之后直接mm即可生成一个fuzz_demo_target，之后将编译好的afl-fuzz（如果使用framework-fuzz下的afl-fuzz则需要给-s和-e参数）和fuzz_demo_target拷贝到安卓设备上即可
./afl-fuzz -i demoin/ -o out/ -s 1633771873 -e 1633771983 -m none -- ./fuzz_demo_target @@