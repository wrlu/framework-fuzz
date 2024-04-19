# android-service-wrapper
- This project will read parameters from file and pass them to Android system services via binder call.

## Requirements
- AOSP source tree with ninja build system (Android 7+), we have tested on Android 10 and Android 12.
- AFL source code, can download from `https://github.com/google/AFL`

## Compile wrapper
- Install requirements of AOSP build tool 
```bash
sudo apt-get install unzip m4 libncurses5 moreutils
```
- Setup AOSP build 
```bash
cd /path/to/aosp
source build/envsetup.sh
lunch aosp_arm64
```

- Compile framework-fuzz project
```bash
cd external
git clone https://github.com/wrlu/android-service-wrapper.git
cd framework-fuzz
mm
```

- Compile Patched AFL source code
We patched original AFL source code to support transaction code generation.
That is to say, the mutated input from AFL consists of two parts: transaction code (the first 4 bytes) and data (the rest bytes).
```bash
cd external
cd framework-fuzz/tools/AFL/
mm
```


- After compile you can find binaries in `out/target/product/aosp_arm64/system/bin`
    - `android-wp-manager`: the client side, it will setup the ashmem, process the stdin parameters and call the target service, you can change the service name and interface in `config.prop`
    - `android-wp-service`: just a test binary for service side, you need to compile service side code with your real target.

## Compile AFL
```bash
cd AOSP/external/AFL && mm
```
If you meet undefined symbol error about dlopen, dlerror, you can add the following part to the compilation command (the command will be prompted to the screen if you meet error) : `out/soong/.intermediates/bionic/libdl/libdl/android_arm64_armv8-a_static/libdl.a`.
It helps the compiler to find the undefined symbol.
Then you can run the full command manually to get the afl-fuzz, it will generated at `out/soong/.intermediates/external/AFL/afl-fuzz/android_arm64_armv8-a/unstripped/afl-fuzz`

## Add code to target service for coverage support
- The original AFL will allocate an shared memory use `/dev/ashmem` on Android and pass the file descriptor using envionment variable. For our target is an Android service but not our android-wp-manager binary, we need pass the file descriptor to service and let service call mmap to map the shared memory.
- We can add these code to target service `onTransact` function:
```cpp
status_t BnDemoService::onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    // Add these code to setup coverage shared memory for fuzzing
    // To use this symbol, do not forget include "service/WpService.h" in a proper header file
    if (hssl::WpService::onTransact(code, data, reply) == android::NO_ERROR) {
        return android::NO_ERROR;
    }

    // Original target service onTransact logic...
}
```
- `hssl::WpService::onTransact` will only handle 2 transaction codes for shared memory set request or unset request.
    - TRANSACTION_SET_ASHMEM: Transaction code for shared memory set, value is `android::IBinder::LAST_CALL_TRANSACTION` (aka. 0x00ffffff)
    - TRANSACTION_UNSET_ASHMEM: Transaction code for shared memory unset, value is `android::IBinder::LAST_CALL_TRANSACTION - 1` (aka. 0x00fffffe)
- These transaction codes are reversed by our fuzzer and do not support config in `config.prop` yet, for most of services they only use small transaction codes so this is often ok.

## Compile target using Android.bp
- First you need to make your target static, replace `cc_library_shared` block with `cc_library_static` block and move them to the `static_libs` but not `shared_libs`.
- And then you need to compile service side code with your real target, you can use `android-wp-service-external-defaults` which defined in Android.bp file. It will extend transaction code logic to setup the shared memory and enable the coverage collection for any module of your target. You can see the example in `service/Main.cpp` and call our `onTransact` method at the first line of the real service one.
```blueprint
cc_library_static {
    name: "your_real_target",

    defaults: [
        // Use this part for every fuzzing target
        "android-wp-service-external-defaults",
    ]
    //...
}
```

## Compile target using legacy Android.mk
- Some target may still use legacy Android.mk makefile, we also provided an example for this situation.
```makefile
# Use this part for every fuzzing target
LOCAL_CFLAGS += -fsanitize-coverage=trace-pc-guard
LOCAL_C_INCLUDES += \
	external/framework-fuzz
LOCAL_STATIC_LIBRARIES += \
	android-wp-service-static
```
- The full example for `android-wp-service` test binary is in `Android.mk`.
- Also remember to make your target static, just replace `BUILD_SHARED_LIBRARIES` command with `BUILD_STATIC_LIBRARIES` command and move them to `LOCAL_SHARED_LIBRARIES` but not `LOCAL_STATIC_LIBRARIES` command.

## HAL support (optional)
- We want to support test HAL services but not finish yet, you can find code in `manager/hal` folder.

## Harmony OS Service Ability (SA) support (optional)
- Harmony OS SA support is an untested feature, you can find code in `manager/sa` folder.

## Customize your test policy
- In default implemetation we just fill in the full Parcel object with data received from fuzzer, if you want to add some custom logic to test you can find code in `manager/custom` folder. The default implemetation is:
```cpp
status TypedParamParser::parseDefault(uint8_t *input, size_t size, android::Parcel &data) {
    if (data.write(input, size) != android::NO_ERROR) {
        ALOGE("[TypedParamParser::parseDefault] Write parcel error.");
        return WP_PARCEL_ERROR;
    }
    return WP_SUCCESS;
}
```
- We can use different policy to fill in the Parcel data, to implement this you need a new parser class to extend `TypedParamParser` class, and write your own policy. - At last you can use `callParser` function to find a proper parser to fill in Parcel data, just like this:
```cpp
static status callParser(uint32_t code, uint8_t *input, size_t size, android::Parcel &data) {
    if (mParserStorage.find(code) != mParserStorage.end()) {
        return mParserStorage[code](input, size, data);
    } else {
        return mParserStorage[0](input, size, data);
    }
}
```
- For different services you need to add logic to `manager/ParamParser.cpp`, and modify this function:
```cpp
status ParamParser::fillData(const std::string& interface) {
    if (mParamFileBuffer == nullptr) {
        ALOGE("[ParamParser::fillData] mParamFileBuffer is nullptr, call loadParam first.");
        return WP_INVALID_PARAM;
    }
    // Select a transaction code
    FuzzedDataProvider provider(mParamFileBuffer, mParamFileSize);
    mCode = provider.ConsumeIntegralInRange(mFirstCall, mLastCall);

    mData.freeData();
    if (mData.writeInterfaceToken(android::String16(interface.c_str())) != android::NO_ERROR) {
        ALOGE("[ParamParser::initParam] Parcel writeInterfaceToken error.");
        return WP_PARCEL_ERROR;
    }
    // Find a proper parser to fill in the Parcel data
    TypedParamParser::callParser(mCode, mParamFileBuffer + sizeof(uint32_t), mParamFileSize - sizeof(uint32_t), mData);

    return WP_SUCCESS;
}
```

## Run

`[NOTICE]` Before fuzzing, please make sure that `trace-pc-guard` works well in your target binary (so/elf). That is to say, there should be `sanitizer_cov_trace_pc_guard` function calls in edges/funcs/bbs.
Sometimes, even if you add `trace-pc-guard` to the clang, it may still fail to instrument the binary without any error.

- You need to setup a config file for the wrapper, the example is in `config/config.prop`
- We support these config item now:
    - SERVICE_NAME: The service name of your target (default value: demo_service)
    - INTERFACE_TOKEN: The interface token of your target (default value: com.example.IDemo)
    - SERVICE_FIRST_CALL: First avaliable transaction code (default value: android::IBinder::FIRST_CALL_TRANSACTION)
    - SERVICE_LAST_CALL: Last avaliable transaction code (default value: android::IBinder::LAST_CALL_TRANSACTION - 2)
    - IS_SA: use SA mode (default value: 0)

- Finally you can run the program with this command. Remember to replace `config.prop` and `input.bin` to your real file path.
```bash
./android-wp-manager config.prop input.bin
```
- If you want to run with AFL, please use this command. For more details please view the AFL project docs.
```bash
./afl-fuzz -i in -o out -m none -s FIRST_CALL -e LAST_CALL ./android-wp-manager config.prop @@

```
FIRST_CALL is the min transaction code and LAST_CALL is the max transaction code.