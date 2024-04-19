/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <time.h>
#include "../utils/status.h"
#include "Preference.h"
#include "WpAshmemManager.h"
#include "WpCrashDetector.h"
#include "WpConfigLoader.h"
#include "WpManager.h"
// #include "hal/WpHwManager.h"
#include "sa/WpSaManager.h"
#include "sa/WpSaAshmemManager.h"
#include "sa/WpSaCrashDetector.h"

#include "service/WpService.h"


#define DEFAULT_SERVICE_NAME "demo_service"
#define DEFAULT_INTERFACE_TOKEN "com.example.IDemo"
#define DEFAULT_IS_SA 0
#define MAX_DEFAULT_CALL_LEN 10

static int isAshmemInit = 0;
// static int isCrashDetectorInit = 0;
static int isConfigInit = 0;

void checkStatus(hssl::status ret) {
    if (ret != 0){
        printf("Find error code = %d", ret);
        exit(ret);
    }
}

void startTestService(std::string& serviceName, std::string& interfaceToken,
    uint32_t firstCall, uint32_t lastCall, const char *params) {

    // if (!isAshmemInit) {
    //     ALOGE("[WpManager::startTestService] isAshmemInit is 0, will Init shmem");
    //     hssl::WpAshmemManager *ashmemManager = 
    //     new hssl::WpAshmemManager(serviceName, interfaceToken);
    //     //ashmemManager->releaseAshmem();
    //     ashmemManager->initAshmem();
    //     isAshmemInit=1;
    // }

    // we should initialize the sharememory every time, since if it crashes we should reset it again?
    hssl::WpAshmemManager *ashmemManager = 
        new hssl::WpAshmemManager(serviceName, interfaceToken);
    // ashmemManager->releaseAshmem();
    ashmemManager->initAshmem();

    // 暂时禁用CrashDetector，在这里使用crashdetector不是一个好主意？
    // 1. 通过日志观察pthread_create并不能保证每次运行之后thread都会启动成功，日志出现以下情况：
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    //  [WpCrashDetector::globalDetectorTask] start global crash detector.
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // 即真正的detector thread并没有按照预期启动
    // 2. 有些目标在编译ASAN之后就会经常挂，这种detector方法可能会有问题：误报多
    // 目前采用的方法是在目标的ontransact函数中添加一个对parcel data的log输出，从而在tombstone生成时，其中包含parcel的信息
    // 但需要注意的是这种记录也并不能完全保证每次的parcel都会被记录在logcat中，因为有一些触发崩溃的请求在发出去之后经过很久才会触发崩溃，此时latest logcat已经无法保证能够复现了

    // if (!isCrashDetectorInit) {
    //     ALOGE("[WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector");
    //     hssl::WpCrashDetector *detector = 
    //     new hssl::WpCrashDetector(serviceName, interfaceToken,
    //     1 /* enableGlobalDetect */);
    //     detector->init();
    //     isCrashDetectorInit = 1;
    // }

    hssl::WpManager manager(serviceName, interfaceToken, firstCall, lastCall);
    checkStatus(manager.init(params));
    // checkStatus(manager.dump());
    // 
    checkStatus(manager.call());

    

}

void startTestSa(int saId, std::string& interfaceToken,
    uint32_t firstCall, uint32_t lastCall, const char *params) {
    if (!isAshmemInit) {
        hssl::WpSaAshmemManager *ashmemManager = 
        new hssl::WpSaAshmemManager(saId, interfaceToken);
        ashmemManager->initAshmem();
        isAshmemInit = 1;
    }
    // 暂时禁用CrashDetector，在这里使用crashdetector不是一个好主意？
    // 1. 通过日志观察pthread_create并不能保证每次运行之后thread都会启动成功，日志出现以下情况：
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    //  [WpCrashDetector::globalDetectorTask] start global crash detector.
    // [WpManager::startTestService] isCrashDetectorInit is 0, will Init Crash Detector
    // 即真正的detector thread并没有按照预期启动

    // if (!isCrashDetectorInit) {
    //     hssl::WpSaCrashDetector *detector = 
    //     new hssl::WpSaCrashDetector(saId, interfaceToken,
    //     1 /* enableGlobalDetect */);
    //     detector->init();
    //     isCrashDetectorInit = 1;
    // }

    hssl::WpSaManager manager(saId, interfaceToken, firstCall, lastCall);
    checkStatus(manager.init(params));
    checkStatus(manager.dump());
    checkStatus(manager.call());
}

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        printf("Usage: ./android-wp-manager configfile @inputfile\n");
        return WP_INVALID_PARAM;
    }

    // char *id_str = getenv(SHM_ENV_VAR);
    // if (id_str != 0) {
    //     int shm_id = atoi(id_str);
    //     __afl_area_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_id, 0));
    // }


    // Init config storage
    hssl::Preference *perference = hssl::Preference::getPreference();

    // Init config
    if (!isConfigInit) {
        hssl::WpConfigLoader *wpConfigLoader = 
            new hssl::WpConfigLoader(argv[1]);
        checkStatus(wpConfigLoader->loadConfig());
        isConfigInit = 1;
    }

    // Read config values
    std::string serviceName = perference->get("SERVICE_NAME",
        DEFAULT_SERVICE_NAME);
    std::string interfaceToken = perference->get("INTERFACE_TOKEN",
        DEFAULT_INTERFACE_TOKEN);
    
    char defaultFirstCall[MAX_DEFAULT_CALL_LEN];
    char defaultLastCall[MAX_DEFAULT_CALL_LEN];
    snprintf(defaultFirstCall, MAX_DEFAULT_CALL_LEN, "%u", android::IBinder::FIRST_CALL_TRANSACTION);
    snprintf(defaultLastCall, MAX_DEFAULT_CALL_LEN, "%u", android::IBinder::LAST_CALL_TRANSACTION - 2);

    uint32_t firstCall = static_cast<uint32_t>(atoi(
        perference->get("SERVICE_FIRST_CALL", defaultFirstCall)));
    uint32_t lastCall = static_cast<uint32_t>(atoi(
        perference->get("SERVICE_LAST_CALL", defaultLastCall)));
    
    int isSa = atoi(perference->get("IS_SA", DEFAULT_IS_SA));

    // Start process
    if (!isSa) {
        startTestService(serviceName, interfaceToken,
            firstCall, lastCall, argv[2]);
    } else {
        int saId = atoi(serviceName.c_str());
        startTestSa(saId, interfaceToken,
            firstCall, lastCall, argv[2]);
    }
    
    return 0;
}