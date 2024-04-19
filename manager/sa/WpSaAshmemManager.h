/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_WP_SA_ASHMEM_MANAGER_H
#define ANDROID_WP_SA_ASHMEM_MANAGER_H

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>

#include <binder/IBinder.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <binder/IServiceManager.h>

#include "SaCaller.h"
#include "../../utils/status.h"

extern "C" {
    // For SHM_ENV_VAR symbol
    #include "../../include/config.h"
}

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpSaAshmemManager"

namespace hssl {

class WpSaAshmemManager {
private:
    SaCaller mSaCaller;
    static const uint32_t TRANSACTION_SET_ASHMEM = android::IBinder::LAST_CALL_TRANSACTION;
    static const uint32_t TRANSACTION_UNSET_ASHMEM = android::IBinder::LAST_CALL_TRANSACTION - 1;
public:
    WpSaAshmemManager(const int saId, const std::string& interface):
        mSaCaller(saId, interface)
        {}
    status initAshmem();
    status releaseAshmem();
};

}
#endif