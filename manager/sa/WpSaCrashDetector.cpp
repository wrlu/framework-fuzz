/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-04
 */
#include "WpSaCrashDetector.h"

namespace hssl {

WpSaCrashDetector::WpSaCrashDetector(int saId, const std::string& interface, int enableGlobalDetect = 0):
    mSaCaller(saId, interface), mDeathRecipient(), mGlobalDetect(enableGlobalDetect) {
}

status WpSaCrashDetector::init() {
    status ret = mSaCaller.tryGetService();
    if (ret != WP_SUCCESS) {
        ALOGE("[WpSaCrashDetector::init] tryGetService failed.");
        return ret;
    }
    if (mGlobalDetect) {
        ALOGD("[WpSaCrashDetector::init] global detect enabled, create detector thread.");
        pthread_create(&mGlobalDetectorThread, nullptr, globalDetectorTask, nullptr);
    }
    return WP_SUCCESS;
}

void *WpSaCrashDetector::globalDetectorTask(void *data) {
    ALOGD("[WpSaCrashDetector::globalDetectorTask] start global crash detector.");
    if (data == nullptr) {
        ALOGW("[WpSaCrashDetector::globalDetectorTask] No parameter.");
    }
    
    int iNotifyFd = inotify_init();
    if (iNotifyFd == -1) {
        ALOGE("[WpSaCrashDetector::globalDetectorTask] inotify_init failed.");
        return nullptr;
    }
    int watchDescriptor = inotify_add_watch(iNotifyFd, PATH_DATA_TOMBSTONE, IN_CREATE);
    if (watchDescriptor == -1) {
        ALOGE("[WpSaCrashDetector::globalDetectorTask] inotify_add_watch failed.");
        close(iNotifyFd);
        return nullptr;
    }
    inotify_event *event = new inotify_event;
    if (event == nullptr) {
        ALOGE("[WpSaCrashDetector::globalDetectorTask] inotify_event malloc error.");
        close(watchDescriptor);
        close(iNotifyFd);
        return nullptr;
    }
    int size = 0;
    while ( (size = read(iNotifyFd, event, sizeof(inotify_event))) != -1 ) {
        if (event->mask & IN_CREATE) {
            ALOGD("[WpSaCrashDetector::globalDetectorTask] crash detected, tombstone path is %s", event->name);
        }
    }
    ALOGD("[WpSaCrashDetector::globalDetectorTask] exit global crash detector.");
    delete event;
    close(watchDescriptor);
    close(iNotifyFd);
    return nullptr;
}

WpSaCrashDetector::~WpSaCrashDetector() {
    if (mGlobalDetect) {
        ALOGD("[WpSaCrashDetector::~WpSaCrashDetector] global detect enabled, exit detector thread.");
        pthread_exit(&mGlobalDetectorThread);
    }
}

}

