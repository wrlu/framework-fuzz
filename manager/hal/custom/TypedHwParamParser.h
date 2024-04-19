/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-06
 */
#ifndef ANDROID_TYPED_HW_PARAM_PARSER_H
#define ANDROID_TYPED_HW_PARAM_PARSER_H

#include <string>
#include <unordered_map>

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <cutils/ashmem.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Log.h>

#include "hwbinder/Parcel.h"

#include "../../utils/status.h"
#include "../../include/FuzzedDataProvider.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "TypedHwParamParser"

namespace hssl {

typedef status (*TypedHwParamParserFuncPtr)(uint8_t*, size_t, android::hardware::Parcel&);

class TypedHwParamParser {
protected:
    static const std::unordered_map<uint32_t, TypedHwParamParserFuncPtr> mHwParserStorage = {
        {0, TypedHwParamParser::parseDefault} // 0 means default parameter parser
    };
public:
    static status callHwParser(uint32_t code, uint8_t *input, size_t size, android::hardware::Parcel &data) {
        if (mHwParserStorage.find(code) != mHwParserStorage.end()) {
            return mHwParserStorage[code](input, size, data);
        } else {
            return mHwParserStorage[0](input, size, data);
        }
    }
    static status parseDefault(uint8_t *input, size_t size, android::hardware::Parcel &data);
};

}
#endif