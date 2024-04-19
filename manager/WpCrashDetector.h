/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#ifndef ANDROID_WP_CRASH_DETECTOR_H
#define ANDROID_WP_CRASH_DETECTOR_H

#include <pthread.h>
#include <sys/inotify.h>
#include <utils/Log.h>
#include <binder/IBinder.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

#include "BinderCaller.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "WpCrashDetector"

#define PATH_DATA_TOMBSTONE "/data/tombstones"

namespace hssl {



class ServiceDeathRecipient : public android::IBinder::DeathRecipient {
public:
    void binderDied(const android::wp<android::IBinder>& who) {
        ALOGE("Target service crash detected !!! who = %p", &who);
    }
};
 
class WpCrashDetector {
private:
    BinderCaller mBinderCaller;
    ServiceDeathRecipient mDeathRecipient;
    pthread_t mGlobalDetectorThread;
    int mGlobalDetect;
public:
    WpCrashDetector(const std::string& serviceName, const std::string& interface,
        int enableGlobalDetect);
    status init();
    static void *globalDetectorTask(void *data);
    const android::IBinder::DeathRecipient& getDeathRecipient() { return mDeathRecipient; }
    ~WpCrashDetector();
};

}
#endif