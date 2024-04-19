/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "WpService.h"

namespace hssl {

// int WpService::ashmemFd = -1;
android::base::unique_fd WpService::ashmemFd;
android::Mutex WpService::m_lock;

android::status_t WpService::onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply) {
    android::Mutex::Autolock lock(m_lock);
    switch (code) {
        case TRANSACTION_SET_ASHMEM: {
            // if (ashmemFd >= 0) {
            //     ALOGE("[WpService::onTransact::TRANSACTION_SET_ASHMEM] ashmemFd already set, call UNSET_ASHMEM first.");
            //     ALOGD("[WpService::onTransact::TRANSACTION_SET_ASHMEM] mmap __afl_area_ptr address %p", __afl_area_ptr);
            //     reply->writeInt32(WP_REMOTE_ASHMEM_ERROR);
            //     return android::FAILED_TRANSACTION;
            // }
            // ashmemFd = data.readFileDescriptor();
            // if (ashmemFd < 0) {
            //     ALOGE("[WpService::onTransact::TRANSACTION_SET_ASHMEM] invalid ashmemFd, ignored.");
            //     // ashmemFd = -1;
            //     reply->writeInt32(WP_REMOTE_ASHMEM_ERROR);
            //     return android::FAILED_TRANSACTION;
            // }
            // __afl_area_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, ashmemFd, 0));
            __afl_area_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, android::base::unique_fd(dup(data.readFileDescriptor())), 0));
            if (__afl_area_ptr == nullptr) {
                ALOGE("[WpService::onTransact::TRANSACTION_SET_ASHMEM] mmap failed."); 
                // ashmemFd = -1;
                reply->writeInt32(WP_REMOTE_ASHMEM_ERROR);
                return android::FAILED_TRANSACTION;
            }
            ALOGD("[WpService::onTransact::TRANSACTION_SET_ASHMEM] mmap __afl_area_ptr address %p", __afl_area_ptr);
            reply->writeInt32(WP_SUCCESS);
            return android::NO_ERROR;
        }
        case TRANSACTION_UNSET_ASHMEM: {
            // if (ashmemFd < 0) {
            //     ALOGE("[WpService::onTransact::TRANSACTION_UNSET_ASHMEM] ashmemFd not set, call SET_ASHMEM first.");
            //     reply->writeInt32(WP_REMOTE_ASHMEM_ERROR);
            //     return android::FAILED_TRANSACTION;
            // }
            // ALOGE("[WpService::onTransact::TRANSACTION_UNSET_ASHMEM] IN TRANSACTION_UNSET_ASHMEM ");
            // munmap(__afl_area_ptr, MAP_SIZE);
            // __afl_area_ptr = __afl_area_initial;
            // close(ashmemFd);
            // ashmemFd = -1;
            reply->writeInt32(WP_SUCCESS);
            return android::NO_ERROR;
        }
        default: {
            return android::UNKNOWN_TRANSACTION;
        }
    }
}
}



