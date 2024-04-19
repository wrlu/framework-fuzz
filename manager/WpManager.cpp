/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "WpManager.h"

// test only starts

#include "hash.h"
// test only ends


namespace hssl {
//
status WpManager::init(const char *configFileName) {
    ALOGE("[WpManager::init] init starts.");
    status ret = mBinderCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpManager::init] tryGetService failed.");
        return ret;
    }
    ret = mParamParser.loadParam(configFileName);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpManager::init] loadParam failed.");
        return ret;
    }
    ret = mParamParser.fillData(mBinderCaller.getInterface());
    if (ret != WP_SUCCESS) {
        ALOGE("[WpManager::init] fillData failed.");
        return ret;
    }
    mParamParser.closeParamFile();

    ALOGE("[WpManager::init] init WP_SUCCESS.");
    return WP_SUCCESS;
}

status WpManager::call() {
    ALOGE("[WpManager::call] call starts, code 0x%x ",mParamParser.getCode());
    
    status s = mBinderCaller.transact(mParamParser.getCode(), mParamParser.getData(), &mParamParser.getReply());


    
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str != 0) {
        int shm_id = atoi(id_str);
        __afl_area_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_id, 0));
        ALOGD("[WpManager::call] __afl_area_ptr address %p", __afl_area_ptr);
        ALOGD("[WpManager::call] __afl_area_ptr[0] %d", __afl_area_ptr[0]);
        ALOGD("[WpManager::call] __afl_area_ptr hash %u", hash32(__afl_area_ptr,65536,0xa5b35705));
    }
    return s;

}

status WpManager::dump() {
    return mParamParser.dumpParam();
}

void WpManager::clean() {
    mParamParser.cleanAll();
}

}
