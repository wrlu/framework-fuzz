/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "WpSaAshmemManager.h"

namespace hssl {

status WpSaAshmemManager::initAshmem() {
    status ret = mSaCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaAshmemManager::initAshmem] SaCaller initBinder failed.");
        return ret;
    }
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str == nullptr) {
        ALOGE("[WpSaAshmemManager::initAshmem] getenv(SHM_ENV_VAR) failed.");
        return WP_AFL_ENV_ERROR;
    }
    int shm_id = atoi(id_str);
    android::Parcel data;
    android::Parcel reply;
    if (data.writeFileDescriptor(shm_id) != android::NO_ERROR) {
        ALOGE("[WpSaAshmemManager::initAshmem] Write shm_id error.");
        return WP_PARCEL_ERROR;
    }
    ret = mSaCaller.transact(TRANSACTION_SET_ASHMEM, data, &reply);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaAshmemManager::initAshmem] SaCaller transact returns error.");
        return ret;
    }
    int remoteStatus = reply.readInt32();
    if (remoteStatus != 0) {
        ALOGE("[WpSaAshmemManager::initAshmem] Remote failed with status code %d.", remoteStatus);
        return WP_REMOTE_ASHMEM_ERROR;
    }
    return WP_SUCCESS;
}

status WpSaAshmemManager::releaseAshmem() {
    android::Parcel data;
    android::Parcel reply;
    ALOGE("[WpSaAshmemManager::releaseAshmem] release ashmem called");
    status ret = mSaCaller.transact(TRANSACTION_UNSET_ASHMEM, data, &reply);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaAshmemManager::releaseAshmem] SaCaller transact returns error.");
        return ret;
    }
    int remoteStatus = reply.readInt32();
    if (remoteStatus != 0) {
        ALOGE("[WpSaAshmemManager::releaseAshmem] Remote failed with status code %d.", remoteStatus);
        return WP_REMOTE_ASHMEM_ERROR;
    }
    return WP_SUCCESS;
}

}