/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#ifndef ANDROID_WP_UTILS_STATUS_H
#define ANDROID_WP_UTILS_STATUS_H

namespace hssl {
    typedef int status;

    #define WP_SUCCESS 0
    #define WP_INVALID_PARAM 1
    #define WP_PARCEL_ERROR 2
    #define WP_AFL_ENV_ERROR 3
    #define WP_REMOTE_SM_ERROR 4
    #define WP_REMOTE_ASHMEM_ERROR 5
    #define WP_REMOTE_NORMAL_ERROR 6
    #define WP_MALLOC_ERROR 7
    #define WP_IO_ERROR 8
    #define WP_REMOTE_SAMGR_ERROR 9
    #define WP_ASHMEM_ERROR 9
}
#endif
