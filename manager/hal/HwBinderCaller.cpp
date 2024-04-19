/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#include "HwBinderCaller.h"

namespace hssl {

status HwBinderCaller::tryGetService() {
    ALOGE("Not implemented!");
    return WP_INVALID_PARAM;
    // android::sp<android::hidl::manager::V1_0::IServiceManager> sm =
    //     android::hardware::defaultServiceManager();
    // mHwRemote = sm->getService(mServiceName);
    // return mHwRemote != nullptr ? WP_SUCCESS : WP_REMOTE_SM_ERROR;
}

status HwBinderCaller::transact(uint32_t code, const android::hardware::Parcel &data, android::hardware::Parcel *reply) {
    if (mHwRemote == nullptr) {
        ALOGE("[HwBinderCaller::transact] Not connect to the hwremote, call initHwBinder first.");
        return WP_REMOTE_SM_ERROR;
    }
    if (mHwRemote->transact(code, data, reply, android::hardware::IBinder::FLAG_ONEWAY) != android::NO_ERROR) {
        ALOGE("[HwBinderCaller::transact] transact returns error.");
        return WP_REMOTE_NORMAL_ERROR;
    }
    return WP_SUCCESS;
}

}
