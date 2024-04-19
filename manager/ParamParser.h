/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_PARAM_PARSER_H
#define ANDROID_PARAM_PARSER_H

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

#include "BaseParamParser.h"
#include "custom/TypedParamParser.h"
#include "../utils/status.h"
#include "../include/FuzzedDataProvider.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "ParamParser"
#define DUMP_FILE_PREFIX "wp-dump-"
#define DUMP_FILE_NAME_MAX_LEN 50
#define DUMP_CODE_BUFFER_MAX_LEN 30
#define DUMP_DATA_PREFIX_LEN 5

namespace hssl {

class ParamParser : public BaseParamParser {
private:
    uint32_t mCode;
    android::Parcel mData;
    android::Parcel mReply;
public:
    ParamParser(uint32_t first, uint32_t last):
        BaseParamParser(first, last)
        {}
    virtual status fillData(const std::string& interface);
    status dumpParam();
    virtual void cleanParamCache();

    uint32_t getCode() { return mCode; }
    android::Parcel& getData() { return mData; }
    android::Parcel& getReply() { return mReply; }

    virtual ~ParamParser() {}
};

}
#endif