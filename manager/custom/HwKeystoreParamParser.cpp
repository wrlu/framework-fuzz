/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-06
 */
#include "HwKeystoreParamParser.h"

namespace hssl {

std::unordered_map<uint32_t, TypedParamParserFuncPtr> HwKeystoreParamParser::mParserStorage = {
    {0, TypedParamParser::parseDefault}, // 0 means default parameter parser
    {android::IBinder::FIRST_CALL_TRANSACTION + 0, HwKeystoreParamParser::parseDel},
    {android::IBinder::FIRST_CALL_TRANSACTION + 1, HwKeystoreParamParser::parseGenerateKey},
    {android::IBinder::FIRST_CALL_TRANSACTION + 2, HwKeystoreParamParser::parseGetKeyCharacteristics},
    {android::IBinder::FIRST_CALL_TRANSACTION + 3, HwKeystoreParamParser::parseExportKey},
    {android::IBinder::FIRST_CALL_TRANSACTION + 4, HwKeystoreParamParser::parseBegin},
    {android::IBinder::FIRST_CALL_TRANSACTION + 5, HwKeystoreParamParser::parseUpdate},
    {android::IBinder::FIRST_CALL_TRANSACTION + 6, HwKeystoreParamParser::parseFinish},
    {android::IBinder::FIRST_CALL_TRANSACTION + 7, HwKeystoreParamParser::parseAbort},
    {android::IBinder::FIRST_CALL_TRANSACTION + 8, HwKeystoreParamParser::parseAttestKey},
    {android::IBinder::FIRST_CALL_TRANSACTION + 9, HwKeystoreParamParser::parseGet},
    {android::IBinder::FIRST_CALL_TRANSACTION + 10, HwKeystoreParamParser::parseSet},
    {android::IBinder::FIRST_CALL_TRANSACTION + 11, HwKeystoreParamParser::parseGetHuksServiceVersion},
    // {android::IBinder::FIRST_CALL_TRANSACTION + 12, HwKeystoreParamParser::parseAttestDeviceIds},
    {android::IBinder::FIRST_CALL_TRANSACTION + 13, HwKeystoreParamParser::parseAssethandleReq},
    {android::IBinder::FIRST_CALL_TRANSACTION + 14, HwKeystoreParamParser::parseExportTrustCert},
    {android::IBinder::FIRST_CALL_TRANSACTION + 15, HwKeystoreParamParser::parseSetKeyProtection},
    {android::IBinder::FIRST_CALL_TRANSACTION + 16, HwKeystoreParamParser::parseContains},
    // {android::IBinder::FIRST_CALL_TRANSACTION + 17, HwKeystoreParamParser::parseAssetRegisterObserver},
    // {android::IBinder::FIRST_CALL_TRANSACTION + 18, HwKeystoreParamParser::parseAssetUnregisterObserver},
    {android::IBinder::FIRST_CALL_TRANSACTION + 19, HwKeystoreParamParser::parseGetSecurityCapabilities},
    {android::IBinder::FIRST_CALL_TRANSACTION + 20, HwKeystoreParamParser::parseGetSecurityChallenge},
    {android::IBinder::FIRST_CALL_TRANSACTION + 21, HwKeystoreParamParser::parseVerifySecurityChallenge},
    // {android::IBinder::FIRST_CALL_TRANSACTION + 22, HwKeystoreParamParser::parseOnUserCredentialChanged},
    // {android::IBinder::FIRST_CALL_TRANSACTION + 23, HwKeystoreParamParser::parseUnlock},
    {android::IBinder::FIRST_CALL_TRANSACTION + 24, HwKeystoreParamParser::parseImportKey},
};

status HwKeystoreParamParser::parseDel(uint8_t *input, size_t size, android::Parcel &data) {
    FuzzedDataProvider provider(input, size);
    int nameLen = provider.ConsumeIntegralInRange(0, 10);
    std::string name = provider.ConsumeBytesAsString(nameLen);
    int uid = provider.ConsumeIntegralInRange(0, 1000);

    data.writeString16(android::String16(name.c_str()));
    data.writeInt32(uid);
    return WP_SUCCESS;
}
status HwKeystoreParamParser::parseGenerateKey(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseGetKeyCharacteristics(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseExportKey(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseBegin(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseUpdate(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseFinish(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseAbort(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseAttestKey(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseGet(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseSet(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseGetHuksServiceVersion(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
// status HwKeystoreParamParser::parseAttestDeviceIds(uint8_t *input, size_t size, android::Parcel &data) {
//     return TypedParamParser::parseDefault(input, size, data);
// }
status HwKeystoreParamParser::parseAssethandleReq(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseExportTrustCert(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseSetKeyProtection(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseContains(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
// status HwKeystoreParamParser::parseAssetRegisterObserver(uint8_t *input, size_t size, android::Parcel &data) {
//     return TypedParamParser::parseDefault(input, size, data);
// }
// status HwKeystoreParamParser::parseAssetUnregisterObserver(uint8_t *input, size_t size, android::Parcel &data) {
//     return TypedParamParser::parseDefault(input, size, data);
// }
status HwKeystoreParamParser::parseGetSecurityCapabilities(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseGetSecurityChallenge(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
status HwKeystoreParamParser::parseVerifySecurityChallenge(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}
// status HwKeystoreParamParser::parseOnUserCredentialChanged(uint8_t *input, size_t size, android::Parcel &data) {
//     return TypedParamParser::parseDefault(input, size, data);
// }
// status HwKeystoreParamParser::parseUnlock(uint8_t *input, size_t size, android::Parcel &data) {
//     return TypedParamParser::parseDefault(input, size, data);
// }
status HwKeystoreParamParser::parseImportKey(uint8_t *input, size_t size, android::Parcel &data) {
    return TypedParamParser::parseDefault(input, size, data);
}

}
