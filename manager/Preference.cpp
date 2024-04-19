/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */

#include "Preference.h"

namespace hssl {

Preference* Preference::mInstance = nullptr;

std::string Preference::get(const std::string& key, const std::string &defaultValue) {
    if (mPreferenceStorage.find(key) != mPreferenceStorage.end()) {
        return mPreferenceStorage[key];
    } else {
        ALOGE("[Preference::get] key %s not found.", key.c_str());
        return defaultValue;
    }
}

const char* Preference::get(const char* key, const char* defaultValue) {
    if (mPreferenceStorage.find(key) != mPreferenceStorage.end()) {
        return mPreferenceStorage[key].c_str();
    } else {
        ALOGE("[Preference::get] key %s not found.", key);
        return defaultValue;
    }
}

void Preference::put(const std::string& key, const std::string& value) {
    ALOGD("[Preference::put] Push key = %s, value = %s.", key.c_str(), value.c_str());
    mPreferenceStorage.emplace(key, value);
}

void Preference::put(const char* key, const char* value) {
    ALOGD("[Preference::put] Push key = %s, value = %s.", key, value);
    std::string keyStr = key;
    std::string valueStr = value;
    mPreferenceStorage.emplace(keyStr, valueStr);
}

}
