/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "WpCrashDetector.h"

namespace hssl {

WpCrashDetector::WpCrashDetector(const std::string& serviceName, const std::string& interface, int enableGlobalDetect = 0):
    mBinderCaller(serviceName, interface), mDeathRecipient(), mGlobalDetect(enableGlobalDetect) {
}

status WpCrashDetector::init() {
    status ret = mBinderCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpCrashDetector::init] tryGetService failed.");
        return ret;
    }
    if (mGlobalDetect) {
        pthread_create(&mGlobalDetectorThread, nullptr, globalDetectorTask, nullptr);
    }
    return WP_SUCCESS;
}

void *WpCrashDetector::globalDetectorTask(void *data) {
    ALOGD("[WpCrashDetector::globalDetectorTask] start global crash detector.");
    if (data == nullptr) ALOGW("[WpCrashDetector::globalDetectorTask] No parameter.");
    int iNotifyFd = inotify_init();
    if (iNotifyFd == -1) {
        ALOGE("[WpCrashDetector::globalDetectorTask] inotify_init failed.");
        return nullptr;
    }
    int watchDescriptor = inotify_add_watch(iNotifyFd, PATH_DATA_TOMBSTONE, IN_CREATE);
    if (watchDescriptor == -1) {
        ALOGE("[WpCrashDetector::globalDetectorTask] inotify_add_watch failed.");
        close(iNotifyFd);
        return nullptr;
    }
    inotify_event *event = new inotify_event;
    if (event == nullptr) {
        ALOGE("[WpCrashDetector::globalDetectorTask] inotify_event malloc error.");
        close(watchDescriptor);
        close(iNotifyFd);
        return nullptr;
    }
    int size = 0;
    while ( (size = read(iNotifyFd, event, sizeof(inotify_event))) != -1 ) {
        if (event->mask & IN_CREATE) {
            ALOGD("[WpCrashDetector::globalDetectorTask] crash detected, tombstone path is %s", event->name);
        }
    }
    ALOGD("[WpCrashDetector::globalDetectorTask] exit global crash detector.");
    delete event;
    close(watchDescriptor);
    close(iNotifyFd);
    return nullptr;
}

WpCrashDetector::~WpCrashDetector() {
    if (mGlobalDetect) {
        pthread_exit(&mGlobalDetectorThread);
    }
}

}

