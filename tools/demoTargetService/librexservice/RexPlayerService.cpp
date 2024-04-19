#define LOG_NDEBUG 0
#define LOG_TAG "RexPlayerService"
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "IRexPlayerService.h"
#include "RexPlayerService.h"

namespace android {

RexPlayerService::RexPlayerService() : mCurrentVal(0),
                                        mLock("RexPlayerServiceLock")
{
    ALOGD("RexPlayerService start \n");
}

RexPlayerService::~RexPlayerService()
{
    ALOGD("RexPlayerService destroyed \n");
}

void RexPlayerService::addSampleData(uint32_t value)
{
    Mutex::Autolock lock(mLock);
    mCurrentVal += value;
    ALOGD("RexPlayerService: addSampleData, mCurrentVal is %d \n",mCurrentVal);
}

};//namespace android
