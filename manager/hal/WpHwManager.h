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

#include "HwBinderCaller.h"
#include "HwParamParser.h"
#include "../../utils/status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpHwManager"

namespace hssl {

class WpHwManager {
private:
    HwBinderCaller mHwBinderCaller;
    HwParamParser mHwParamParser;
public:
    WpHwManager(const std::string& serviceName, const std::string& interface, 
        uint32_t first, uint32_t last):
        mHwBinderCaller(serviceName, interface), mHwParamParser(first, last)
        {}
    status init(const char *configFileName);
    status call();
    status dump();
    void clean();
};

}
#endif