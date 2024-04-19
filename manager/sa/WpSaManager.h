/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_WP_SA_MANAGER_H
#define ANDROID_WP_SA_MANAGER_H

#include <string>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>

#include <binder/IBinder.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <binder/IServiceManager.h>

#include "../BinderCaller.h"
#include "../WpManager.h"
#include "../../utils/status.h"
#include "SaCaller.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpSaManager"

namespace hssl {

class WpSaManager {
    SaCaller mSaCaller;
    ParamParser mParamParser;
public:
    WpSaManager(int saId, const std::string& interface, 
        uint32_t first, uint32_t last):
        mSaCaller(saId, interface), mParamParser(first, last)
        {}
    status init(const char *configFileName);
    status call();
    status dump();
};

}
#endif