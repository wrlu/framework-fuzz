/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#ifndef ANDROID_HW_BINDER_CALLER_H
#define ANDROID_HW_BINDER_CALLER_H

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Log.h>

#include "hwbinder/IBinder.h"
#include "hwbinder/Parcel.h"

#include <hidl/ServiceManagement.h>

#include "../../utils/status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "HwBinderCaller"

namespace hssl {

class HwBinderCaller {
private:
    std::string mServiceName;
    std::string mInterface;

    android::sp<android::hardware::IBinder> mHwRemote;
public:
    HwBinderCaller(const std::string& serviceName, const std::string& interface):
        mServiceName(serviceName),
        mInterface(interface)
        {}
    
    status tryGetService();

    status transact(uint32_t code, const android::hardware::Parcel &data, android::hardware::Parcel *reply);

    const std::string& getServiceName() { return mServiceName; }
    void setServiceName(const std::string& name) { mServiceName = name; }
    const std::string& getInterface() { return mInterface; }
    void setInterface(const std::string& interface) { mInterface = interface; }
};

}
#endif