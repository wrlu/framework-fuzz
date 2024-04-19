/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "BinderCaller.h"

namespace hssl {

status BinderCaller::tryGetService() {
    android::sp<android::IServiceManager> sm =
        android::defaultServiceManager();
    mRemote = sm->getService(android::String16(mServiceName.c_str()));
    return mRemote != nullptr ? WP_SUCCESS : WP_REMOTE_SM_ERROR;
}

status BinderCaller::transact(uint32_t code, const android::Parcel &data, android::Parcel *reply) {
    if (mRemote == nullptr) {
        ALOGE("[BinderCaller::transact] Not connect to the remote, call initBinder first.");
        return WP_REMOTE_SM_ERROR;
    }
    ALOGE("[BinderCaller::transact] will call mRemote->transact: code: %d (0x%02x)\n",code,code);
    // status result = mRemote->transact(code, data, reply, android::IBinder::FLAG_ONEWAY);
    // TODO 不要使用oneway，否则可能导致AFL无法记录每一个case对应的代码覆盖
    status result = mRemote->transact(code, data, reply);
    if ( result != android::NO_ERROR) {
        ALOGE("[BinderCaller::transact] Transact Returns Error: 0x%x",result);
        return WP_REMOTE_NORMAL_ERROR;
    }
    return WP_SUCCESS;
}

}
