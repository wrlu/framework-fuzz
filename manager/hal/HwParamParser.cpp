/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#include "HwParamParser.h"

namespace hssl {

status HwParamParser::fillData(const std::string& interface) {
    if (mParamFileBuffer == nullptr) {
        ALOGE("[HwParamParser::fillData] mParamFileBuffer is nullptr, call loadParam first.");
        return WP_INVALID_PARAM;
    }
    // Select a transaction code
    FuzzedDataProvider provider(mParamFileBuffer, mParamFileSize);
    mCode = provider.ConsumeIntegralInRange(mFirstCall, mLastCall);

    mData.freeData();
    // HwBinder does not use String16
    if (mData.writeInterfaceToken(interface.c_str()) != android::NO_ERROR) {
        ALOGE("[ParamParser::initParam] Parcel writeInterfaceToken error.");
        return WP_PARCEL_ERROR;
    }
    // Fill in the Parcel data
    TypedParamParser::callHwParser(mCode, mParamFileBuffer + sizeof(uint32_t), mParamFileSize - sizeof(uint32_t), mData);

    return WP_SUCCESS;
}

status HwParamParser::dumpParam() {
    size_t dataSize = mData.dataSize();
    if (dataSize == 0) {
        ALOGE("[HwParamParser::dumpParam] No data in parcel object.");
        return WP_PARCEL_ERROR;
    }
    char fullFileName[DUMP_FILE_NAME_MAX_LEN];
    time_t t;
    time(&t);
    snprintf(fullFileName, DUMP_FILE_NAME_MAX_LEN, "%s%ld.bin", DUMP_FILE_PREFIX, t);
    
    int fd = open(fullFileName, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        ALOGE("[ParamParser::dumpParam] Cannot open dump log file.");
        return WP_IO_ERROR;
    }
    // Write transact code
    char codeBuffer[DUMP_CODE_BUFFER_MAX_LEN];
    snprintf(codeBuffer, DUMP_CODE_BUFFER_MAX_LEN, "code=%u\n", mCode);
    write(fd, codeBuffer, strnlen(codeBuffer, DUMP_CODE_BUFFER_MAX_LEN));

    // Write parcel data
    write(fd, "data=", DUMP_DATA_PREFIX_LEN);
    uint8_t* dataBuffer = new uint8_t[dataSize];

    if (dataBuffer == nullptr) {
        ALOGE("[ParamParser::dumpParam] malloc failed.");
        return WP_IO_ERROR;
    }

    // If we read immediately after initParam called, we need to move data position to 0.
    mData.setDataPosition(0);
    if (mData.read(dataBuffer, dataSize) != android::NO_ERROR) {
        ALOGE("[ParamParser::dumpParam] Read parcel error.");
        return WP_PARCEL_ERROR;
    }

    if (write(fd, dataBuffer, dataSize) == -1) {
        ALOGE("[ParamParser::dumpParam] Write file failed.");
        return WP_IO_ERROR;
    }
    write(fd, "\n", 1);
    close(fd);
    
    return WP_SUCCESS;
}

void HwParamParser::cleanParamCache() {
    mCode = 0;
    mData.freeData();
    mReply.freeData();
}

}
