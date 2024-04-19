/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "WpAshmemManager.h"

namespace hssl {

status WpAshmemManager::initAshmem() {
    status ret = mBinderCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpAshmemManager::init] initBinder failed.");
        return ret;
    }
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str == nullptr) {
        ALOGE("[WpAshmemManager::initAshmem] getenv(SHM_ENV_VAR) failed.");
        return WP_AFL_ENV_ERROR;
    }
    int shm_id = atoi(id_str);
    ALOGE("[WpAshmemManager::initAshmem] shm_id is %d",shm_id);
    android::Parcel data;
    android::Parcel reply;
    if (data.writeFileDescriptor(shm_id) != android::NO_ERROR) {
        ALOGE("[WpAshmemManager::initAshmem] Write shm_id error.");
        return WP_PARCEL_ERROR;
    }
    ALOGE("[WpAshmemManager::initAshmem] transact will be called");
    ret = mBinderCaller.transact(TRANSACTION_SET_ASHMEM, data, &reply);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpAshmemManager::initAshmem] BinderCaller transact returns error: %u",ret);
        return ret;
    }
    int remoteStatus = reply.readInt32();
    if (remoteStatus != 0) {
        ALOGE("[WpAshmemManager::initAshmem] Remote failed with status code %d.", remoteStatus);
        return WP_REMOTE_ASHMEM_ERROR;
    }
    return WP_SUCCESS;
}

status WpAshmemManager::releaseAshmem() {
    android::Parcel data;
    android::Parcel reply;
    status ret = mBinderCaller.tryGetService();
    ret = mBinderCaller.transact(TRANSACTION_UNSET_ASHMEM, data, &reply);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpAshmemManager::releaseAshmem] SaCaller transact returns error.");
        return ret;
    }
    int remoteStatus = reply.readInt32();
    if (remoteStatus != 0) {
        ALOGE("[WpAshmemManager::releaseAshmem] Remote failed with status code %d.", remoteStatus);
        return WP_REMOTE_ASHMEM_ERROR;
    }
    return WP_SUCCESS;
}

}