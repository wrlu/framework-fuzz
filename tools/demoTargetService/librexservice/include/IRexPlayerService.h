#ifndef IREXPLAYERSERVICE_H
#define IREXPLAYERSERVICE_H
#include <binder/IInterface.h>

namespace android
{
static const char* REX_PLAYER_SERVICE = "rex.player";

class Parcel;

class IRexPlayerService : public IInterface
{
public:
    DECLARE_META_INTERFACE(RexPlayerService);

    virtual void addSampleData(uint32_t value) = 0;
};

class BnRexPlayerService : public BnInterface<IRexPlayerService>
{
public:
    virtual status_t onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags = 0);
};

}; //namespace android

#endif
