#define LOG_TAG "RexPlayerServerMain"
#define LOG_NDEBUG 0

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <cutils/properties.h>
#include <fcntl.h>
#include <utils/Log.h>

#include "RexPlayerService.h"



using namespace android;

int main(int argc __unused, char **argv __unused)
{
    sp<ProcessState> proc(ProcessState::self());
    sp<IServiceManager> sm = defaultServiceManager();

    ALOGE("RexPlayerServerMain: sm: %p", sm.get());
    sp<RexPlayerService> mService = new RexPlayerService();
    sm->addService(String16(REX_PLAYER_SERVICE),mService);

    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();
}
