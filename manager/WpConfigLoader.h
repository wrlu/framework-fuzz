/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_WP_CONFIG_LOADER_H
#define ANDROID_WP_CONFIG_LOADER_H

#include <string>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utils/Log.h>

#include "Preference.h"
#include "../utils/status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpConfigLoader"
#define WP_MAX_PROPERTY_KEY_LEN 50
#define WP_MAX_PROPERTY_VALUE_LEN 500

namespace hssl {

class WpConfigLoader {
private:
    std::string configFile;
public:
    WpConfigLoader(const std::string& configFilename): configFile(configFilename) {}
    WpConfigLoader(const char* configFilename): configFile(configFilename) {}
    status loadConfig();
};

}
#endif  