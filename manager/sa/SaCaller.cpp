/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */

#include "SaCaller.h"

namespace hssl {

status SaCaller::tryGetService() {
    // Call initBinder of BinderCaller to get samgr remote object
    if (BinderCaller::tryGetService() == WP_REMOTE_SM_ERROR) {
        ALOGE("[SaCaller::tryGetService] BinderCaller::initBinder failed.");
        return WP_REMOTE_SM_ERROR;
    }
    // mRemote is samgr remote binder
    if (mRemote == nullptr) {
        ALOGE("[SaCaller::tryGetService] samgrRemote is nullptr.");
        return WP_REMOTE_SAMGR_ERROR;
    }
    // Get real SA remote object from samgr
    android::Parcel data;
    android::Parcel reply;
    data.writeInt32(mSaId);
    if (mRemote->transact(TRANSACTION_CHECK_SA, data, &reply, android::IBinder::FLAG_ONEWAY) != android::NO_ERROR) {
        ALOGE("[SaCaller::tryGetService] samgrRemote->transact returns error.");
        return WP_REMOTE_SAMGR_ERROR;
    }
    mSaRemote = reply.readStrongBinder();
    return mSaRemote != nullptr ? WP_SUCCESS : WP_REMOTE_SAMGR_ERROR;
}

}
