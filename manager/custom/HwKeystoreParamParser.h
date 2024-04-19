/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-05
 */
#ifndef ANDROID_HW_KEYSTORE_PARAM_PARSER_H
#define ANDROID_HW_KEYSTORE_PARAM_PARSER_H

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
#include "TypedParamParser.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "HwKeystoreParamParser"

#ifdef TYPED_PARAM_PARSER_SERVICE_NAME
#undef TYPED_PARAM_PARSER_SERVICE_NAME
#endif

#define TYPED_PARAM_PARSER_SERVICE_NAME "com.huawei.security.IHwKeystoreService"

namespace hssl {

typedef status (*TypedParamParserFuncPtr)(uint8_t*, size_t, android::Parcel&);

class HwKeystoreParamParser : public TypedParamParser {
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
    static status parseDel(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGenerateKey(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGetKeyCharacteristics(uint8_t *input, size_t size, android::Parcel &data);
    static status parseExportKey(uint8_t *input, size_t size, android::Parcel &data);
    static status parseBegin(uint8_t *input, size_t size, android::Parcel &data);
    static status parseUpdate(uint8_t *input, size_t size, android::Parcel &data);
    static status parseFinish(uint8_t *input, size_t size, android::Parcel &data);
    static status parseAbort(uint8_t *input, size_t size, android::Parcel &data);
    static status parseAttestKey(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGet(uint8_t *input, size_t size, android::Parcel &data);
    static status parseSet(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGetHuksServiceVersion(uint8_t *input, size_t size, android::Parcel &data);
    // static status parseAttestDeviceIds(uint8_t *input, size_t size, android::Parcel &data);
    static status parseAssethandleReq(uint8_t *input, size_t size, android::Parcel &data);
    static status parseExportTrustCert(uint8_t *input, size_t size, android::Parcel &data);
    static status parseSetKeyProtection(uint8_t *input, size_t size, android::Parcel &data);
    static status parseContains(uint8_t *input, size_t size, android::Parcel &data);
    // static status parseAssetRegisterObserver(uint8_t *input, size_t size, android::Parcel &data);
    // static status parseAssetUnregisterObserver(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGetSecurityCapabilities(uint8_t *input, size_t size, android::Parcel &data);
    static status parseGetSecurityChallenge(uint8_t *input, size_t size, android::Parcel &data);
    static status parseVerifySecurityChallenge(uint8_t *input, size_t size, android::Parcel &data);
    // static status parseOnUserCredentialChanged(uint8_t *input, size_t size, android::Parcel &data);
    // static status parseUnlock(uint8_t *input, size_t size, android::Parcel &data);
    static status parseImportKey(uint8_t *input, size_t size, android::Parcel &data);
};

}
#endif