/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "WpConfigLoader.h"

namespace hssl {

status WpConfigLoader::loadConfig() {
    const char *filename = configFile.c_str();
    struct stat fileStat;
    if (stat(filename, &fileStat) != 0) {
        ALOGE("[WpConfigLoader::loadConfig] Cannot get file size: %s", filename);
        return WP_IO_ERROR;
    }
    int fileSize = fileStat.st_size;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        ALOGE("[WpConfigLoader::loadConfig] Cannot open file: %s", filename);
        return WP_IO_ERROR;
    }
    char *buffer = new char[fileSize];
    if (buffer == nullptr) {
        ALOGE("[WpConfigLoader::loadConfig] malloc failed.");
        return WP_MALLOC_ERROR;
    }

    if (read(fd, buffer, fileSize) == -1) {
        ALOGE("[WpConfigLoader::loadConfig] read file failed.");
        return WP_IO_ERROR;
    }

    Preference *preference = hssl::Preference::getPreference();
    char keyBuffer[WP_MAX_PROPERTY_KEY_LEN + 1];
    char valueBuffer[WP_MAX_PROPERTY_VALUE_LEN + 1];
    int count = 0;
    int switchReadValue = 0;

    for (int i = 0; i < fileSize; ++i) {
        if (!switchReadValue) {
            if (buffer[i] == ':') {
                if (count <= WP_MAX_PROPERTY_KEY_LEN) {
                    keyBuffer[count] = '\0';
                } else {
                    ALOGW("[WpConfigLoader::loadConfig] config key length overflow, give up %d chars!",
                        count - WP_MAX_PROPERTY_KEY_LEN);
                }
                switchReadValue = 1;
                count = 0;
            } else {
                if (count > WP_MAX_PROPERTY_KEY_LEN) {
                    keyBuffer[count] = '\0';
                } else {
                    keyBuffer[count] = buffer[i];
                    ++count;
                }
            }
        } else {
            if (buffer[i] == '\n' || i + 1 == fileSize) {
                if (count <= WP_MAX_PROPERTY_VALUE_LEN) {
                    valueBuffer[count] = '\0';
                } else {
                    ALOGW("[WpConfigLoader::loadConfig] Config value length overflow, give up %d chars!",
                        count - WP_MAX_PROPERTY_VALUE_LEN);
                }
                switchReadValue = 0;
                count = 0;
                preference->put(keyBuffer, valueBuffer);
                memset(keyBuffer, 0, WP_MAX_PROPERTY_KEY_LEN + 1);
                memset(valueBuffer, 0, WP_MAX_PROPERTY_VALUE_LEN + 1);
            } else {
                if (count > WP_MAX_PROPERTY_VALUE_LEN) {
                    valueBuffer[count] = '\0';
                    continue;
                } else {
                    valueBuffer[count] = buffer[i];
                    ++count;
                }
            }
        }
    }
    return WP_SUCCESS;
}

}
