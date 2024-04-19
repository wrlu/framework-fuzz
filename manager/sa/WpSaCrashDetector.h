/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_WP_SA_CRASH_DETECTOR_H
#define ANDROID_WP_SA_CRASH_DETECTOR_H

#include <pthread.h>
#include <sys/inotify.h>
#include <binder/IBinder.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

#include "SaCaller.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpSaCrashDetector"

#define PATH_DATA_TOMBSTONE "/data/tombstones"

namespace hssl {



class SaDeathRecipient : public android::IBinder::DeathRecipient {
public:
    void binderDied(const android::wp<android::IBinder>& who) {
        ALOGE("Target service crash detected !!! who = %p", &who);
    }
};
 
class WpSaCrashDetector {
private:
    SaCaller mSaCaller;
    SaDeathRecipient mDeathRecipient;
    pthread_t mGlobalDetectorThread;
    int mGlobalDetect;
public:
    WpSaCrashDetector(int saId, const std::string& interface,
        int enableGlobalDetect);
    status init();
    static void *globalDetectorTask(void *data);
    const android::IBinder::DeathRecipient& getDeathRecipient() { return mDeathRecipient; }
    ~WpSaCrashDetector();
};

}
#endif