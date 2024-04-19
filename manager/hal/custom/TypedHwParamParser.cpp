/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#include "TypedHwParamParser.h"

namespace hssl {

status TypedHwParamParser::parseDefault(uint8_t *input, size_t size, android::hardware::Parcel &data) {
    if (data.write(input, size) != android::NO_ERROR) {
        ALOGE("[TypedHwParamParser::parseDefault] Write parcel error.");
        return WP_PARCEL_ERROR;
    }
    return WP_SUCCESS;
}

}