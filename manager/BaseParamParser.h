/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#ifndef ANDROID_BASE_PARAM_PARSER_H
#define ANDROID_BASE_PARAM_PARSER_H

#include <string>

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Log.h>

#include <binder/Parcel.h>

#include "custom/TypedParamParser.h"
#include "../utils/status.h"
#include "../include/FuzzedDataProvider.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "BaseParamParser"

namespace hssl {

class BaseParamParser {
protected:
    uint32_t mFirstCall;
    uint32_t mLastCall;
    uint8_t* mParamFileBuffer;
    int mParamFd;
    uint64_t mParamFileSize;
public:
    BaseParamParser(uint32_t first, uint32_t last):
        mFirstCall(first), mLastCall(last)
        {}
    status loadParam(const char *filename);
    virtual status fillData(const std::string& interface) = 0;
    void closeParamFile();
    virtual void cleanParamCache() = 0;
    void cleanAll();
    virtual ~BaseParamParser() {}
};

}
#endif