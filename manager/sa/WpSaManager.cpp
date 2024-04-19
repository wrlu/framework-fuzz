/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "WpSaManager.h"

namespace hssl {

status WpSaManager::init(const char *configFileName) {
    status ret = mSaCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaManager::init] tryGetService failed.");
        return ret;
    }
    ret = mParamParser.loadParam(configFileName);
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaManager::init] loadParam failed.");
        return ret;
    }
    ret = mParamParser.fillData(mSaCaller.getInterface());
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaManager::init] fillData failed.");
        return ret;
    }
    mParamParser.closeParamFile();
    return WP_SUCCESS;
}

status WpSaManager::call() {
    ALOGE("[WpSaManager::call] call function starts");
    return mSaCaller.transact(mParamParser.getCode(), mParamParser.getData(), &mParamParser.getReply());
}

status WpSaManager::dump() {
    return mParamParser.dumpParam();
}

}
