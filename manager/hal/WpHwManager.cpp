/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "WpHwManager.h"

namespace hssl {

status WpHwManager::init(const char *configFileName) {
    status ret = mHwBinderCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpHwManager::init] tryGetService failed.");
        return ret;
    }
    ret = mHwParamParser.loadParam(configFileName);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpHwManager::init] loadParam failed.");
        return ret;
    }
    ret = mHwParamParser.fillData(mHwBinderCaller.getInterface());
    if (ret != WP_SUCCESS) {
        ALOGE("[WpHwManager::init] fillData failed.");
        return ret;
    }
    mHwParamParser.closeParamFile();
    return WP_SUCCESS;
}

status WpHwManager::call() {
    return mHwBinderCaller.transact(mHwParamParser.getCode(), mHwParamParser.getData(), &mHwParamParser.getReply());
}

status WpHwManager::dump() {
    return mHwParamParser.dumpParam();
}

void WpHwManager::clean() {
    mHwParamParser.cleanAll();
}

}
