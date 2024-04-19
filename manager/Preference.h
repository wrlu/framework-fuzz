/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_PREFERENCE_H
#define ANDROID_PREFERENCE_H

#include <string>
#include <unordered_map>
#include <sys/types.h>
#include <sys/stat.h>
#include <utils/Log.h>

#include "../utils/status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "Preference"

namespace hssl {

class Preference {
private:
    static Preference* mInstance;
    std::unordered_map<std::string, std::string> mPreferenceStorage;
    Preference() {}
public:
    static Preference* getPreference() {
        if (mInstance == nullptr) {
            mInstance = new Preference();
        }
        return mInstance;
    }
    std::string get(const std::string& key, const std::string &defaultValue);
    const char* get(const char* key, const char* defaultValue);
    void put(const std::string& key, const std::string& value);
    void put(const char* key, const char* value);
};

}
#endif  