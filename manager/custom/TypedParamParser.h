/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#ifndef ANDROID_TYPED_PARAM_PARSER_H
#define ANDROID_TYPED_PARAM_PARSER_H

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

#include <binder/Parcel.h>

#include "../../utils/status.h"
#include "../../include/FuzzedDataProvider.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "TypedParamParser"

#ifdef TYPED_PARAM_PARSER_SERVICE_NAME
#undef TYPED_PARAM_PARSER_SERVICE_NAME
#endif

#define TYPED_PARAM_PARSER_SERVICE_NAME "default"

namespace hssl {

typedef status (*TypedParamParserFuncPtr)(uint8_t*, size_t, android::Parcel&);

class TypedParamParser {
private:
    static std::unordered_map<uint32_t, TypedParamParserFuncPtr> mParserStorage;
public:
    static status callParser(uint32_t code, uint8_t *input, size_t size, android::Parcel &data) {
        if (mParserStorage.find(code) != mParserStorage.end()) {
            return mParserStorage[code](input, size, data);
        } else {
            return mParserStorage[0](input, size, data);
        }
    }
    static std::string getServiceName() {
        return std::string(TYPED_PARAM_PARSER_SERVICE_NAME);
    }
    static status parseDefault(uint8_t *input, size_t size, android::Parcel &data);
    static status parseFileDescriptor(uint8_t *input, size_t size, android::Parcel &data);
};

}
#endif