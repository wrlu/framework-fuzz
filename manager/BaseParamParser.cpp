/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#include "BaseParamParser.h"

namespace hssl {

status BaseParamParser::loadParam(const char *inputFileName) {
    struct stat fileStat;
    if (stat(inputFileName, &fileStat) != 0) {
        ALOGE("[ParamParser::initParam] Cannot get file size: %s", inputFileName);
        return WP_IO_ERROR;
    }
    mParamFileSize = fileStat.st_size;
    if (mParamFileSize < sizeof(uint32_t)) {
        ALOGE("[ParamParser::initParam] Invalid file size.");
        return WP_INVALID_PARAM;
    }

    mParamFd = open(inputFileName, O_RDONLY);
    if (mParamFd == -1) {
        ALOGE("[ParamParser::initParam] Cannot open file: %s", inputFileName);
        return WP_IO_ERROR;
    }

    mParamFileBuffer = reinterpret_cast<uint8_t*>(mmap(nullptr, mParamFileSize, PROT_READ, MAP_PRIVATE, mParamFd, 0));

    if (mParamFileBuffer == nullptr) {
        ALOGE("[ParamParser::initParam] Read buffer mmap failed.");
        return WP_MALLOC_ERROR;
    }

    return WP_SUCCESS;
}

void BaseParamParser::closeParamFile() {
    munmap(mParamFileBuffer, mParamFileSize);
    close(mParamFd);
    mParamFileBuffer = 0;
    mParamFd = -1;
    mParamFileSize = 0;
}

void BaseParamParser::cleanAll() {
    closeParamFile();
    cleanParamCache();
}

}
