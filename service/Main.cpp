/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "WpService.h"

int main() {
    android::Parcel data, reply;
    hssl::WpService::onTransact(0, data, &reply);
    return 0;
}