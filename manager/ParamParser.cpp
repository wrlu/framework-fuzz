/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "ParamParser.h"
#include <iostream>
#include <time.h>

namespace hssl {

status ParamParser::fillData(const std::string& interface) {
    ALOGE("[ParamParser::fillData] fillData call starts");
    if (mParamFileBuffer == nullptr) {
        ALOGE("[ParamParser::fillData] mParamFileBuffer is nullptr, call loadParam first.");
        return WP_INVALID_PARAM;
    }
    // Select a transaction code
    //@Puzzor 这里的transaction code的选择方法有局限，ConsumeIntegralInRange出来的的值并不是均匀分布的（和变异的输入内容有关系）
    FuzzedDataProvider provider(mParamFileBuffer, mParamFileSize);
    // mCode = provider.ConsumeIntegralInRange(mFirstCall, mLastCall);
    
    provider.ConsumeData(&mCode,4);
    
    //srand(time(NULL));
    //mCode = rand()%(mLastCall-mFirstCall + 1) + mFirstCall;

    ALOGE("[ParamParser::fillData] choose mCode with %u",mCode);
    mData.freeData();
    if (mData.writeInterfaceToken(android::String16(interface.c_str())) != android::NO_ERROR) {
        ALOGE("[ParamParser::initParam] Parcel writeInterfaceToken error.");
        return WP_PARCEL_ERROR;
    }
    ALOGE("[ParamParser::fillData] will find a proper parser to pase the mParamFileBuffer into mData");
    // Find a proper parser to fill in the Parcel data
    TypedParamParser::callParser(mCode, mParamFileBuffer + sizeof(uint32_t)  /*mCode*/, mParamFileSize - sizeof(uint32_t), mData);

    return WP_SUCCESS;
}

status ParamParser::dumpParam() {
    size_t dataSize = mData.dataSize();
    if (dataSize == 0) {
        ALOGE("[ParamParser::dumpParam] No data in parcel object.");
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

void ParamParser::cleanParamCache() {
    mCode = 0;
    mData.freeData();
    mReply.freeData();
}

}
