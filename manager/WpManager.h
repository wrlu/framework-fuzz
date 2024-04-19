/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#ifndef ANDROID_WP_MANAGER_H
#define ANDROID_WP_MANAGER_H

#include <string>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Log.h>

#include <binder/IBinder.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <binder/IServiceManager.h>

#include "BinderCaller.h"
#include "ParamParser.h"
#include "../utils/status.h"

#include "config.h"
#include "types.h"

extern u8* __afl_area_ptr;

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpManager"

namespace hssl {

class WpManager {
private:
    BinderCaller mBinderCaller;
    ParamParser mParamParser;
public:
    WpManager(const std::string& serviceName, const std::string& interface, 
        uint32_t first, uint32_t last):
        mBinderCaller(serviceName, interface), mParamParser(first, last)
        {}
    status init(const char *configFileName);
    status call();
    status dump();
    void clean();
};

}
#endif