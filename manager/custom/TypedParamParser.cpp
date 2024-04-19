/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#include "TypedParamParser.h"

namespace hssl {

std::unordered_map<uint32_t, TypedParamParserFuncPtr> TypedParamParser::mParserStorage = {
    {0, TypedParamParser::parseDefault} // 0 means default parameter parser
};

status TypedParamParser::parseDefault(uint8_t *input, size_t size, android::Parcel &data) {
    
    ALOGE("[TypedParamParser::parseDefault] Write parcel start.");
    if (data.write(input, size) != android::NO_ERROR) {
        ALOGE("[TypedParamParser::parseDefault] Write parcel error.");
        return WP_PARCEL_ERROR;
    }
    return WP_SUCCESS;
}

status TypedParamParser::parseFileDescriptor(uint8_t *input, size_t size, android::Parcel &data) {
    int ashmemFd = ashmem_create_region("android-wp-manager", size);
    if (ashmemFd < 0) {
        ALOGE("[TypedParamParser::parseFileDescriptor] invalid ashmemFd, ignored.");
        return WP_ASHMEM_ERROR;
    }
    uint8_t *target = reinterpret_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, ashmemFd, 0));
    if (target == nullptr) {
        ALOGE("[TypedParamParser::parseFileDescriptor] mmap failed."); 
        return WP_ASHMEM_ERROR;
    }
    memcpy(target, input, size);
    if (data.writeFileDescriptor(ashmemFd) != android::NO_ERROR) {
        ALOGE("[TypedParamParser::parseFileDescriptor] Write ashmemFd error.");
        return WP_PARCEL_ERROR;
    }
    return WP_SUCCESS;
}

}