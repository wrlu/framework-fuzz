/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_SA_CALLER_H
#define ANDROID_SA_CALLER_H

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
#include "../../utils/status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define SAMGR_SERVICE_NAME "SamgrService"
#define TRANSACTION_CHECK_SA 2

#define LOG_TAG "SaCaller"

namespace hssl {

class SaCaller : public BinderCaller {
private:
    int mSaId;
    std::string mSaInterface;
    android::sp<android::IBinder> mSaRemote;
public:
    SaCaller(int saId, const std::string& saInterface):
        BinderCaller(SAMGR_SERVICE_NAME, ""), mSaId(saId), mSaInterface(saInterface)
        {}
    status tryGetService();

    int getSaId() { return mSaId; }
    void setSaId(const int id) { mSaId = id; }
    const std::string& getSaInterface() { return mSaInterface; }
    void setSaInterface(const std::string& interface) { mSaInterface = interface; }
};

}
#endif