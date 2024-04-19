#ifndef REXPLAYERSERVICE_H
#define REXPLAYERSERVICE_H

#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>

#include "IRexPlayerService.h"

namespace android {
class RexPlayerService : public BnRexPlayerService
{
public:
    RexPlayerService();
    virtual ~RexPlayerService();

    virtual void addSampleData(uint32_t value);
private:
    uint32_t mCurrentVal;
    Mutex mLock;
};

};//namespace android

#endif
