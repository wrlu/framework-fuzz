/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#ifndef ANDROID_WP_SERVICE_H
#define ANDROID_WP_SERVICE_H

#include <string>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/threads.h>

#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

#include "../utils/status.h"

extern "C" {
    //puzzor fix here
    // #include "../include/config.h"
    // #include "../include/types.h"

    #include "../tools/AFL/config.h"
    #include "../tools/AFL/types.h"
}

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpService"

extern u8  __afl_area_initial[MAP_SIZE];
extern u8* __afl_area_ptr;

namespace hssl {

class WpService {
private:
    static const uint32_t TRANSACTION_SET_ASHMEM = android::IBinder::LAST_CALL_TRANSACTION;
    static const uint32_t TRANSACTION_UNSET_ASHMEM = android::IBinder::LAST_CALL_TRANSACTION - 1;
    
    static android::Mutex m_lock;
    WpService() {}
    WpService(WpService &) {}
public:
    // static int ashmemFd;
    static android::base::unique_fd ashmemFd;
    static android::status_t onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply);
};

}

#endif
