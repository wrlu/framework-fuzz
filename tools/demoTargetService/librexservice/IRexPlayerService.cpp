#define LOG_NDEBUG 0
#define LOG_TAG "IRexPlayerService"
#include <utils/Log.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <binder/Parcel.h>
#include <stdint.h>

#include "IRexPlayerService.h"

#include "service/WpService.h"

#include "hash.h"
#include "config.h"


extern u8* __afl_area_ptr;

namespace android {
    enum{
        CODE1= IBinder::FIRST_CALL_TRANSACTION,
        CODE2,
        CODE3,
        CODE4,
        CODE5,
        
    };

class BpRexPlayerService : public BpInterface<IRexPlayerService>
{
public:
    explicit BpRexPlayerService(const sp<IBinder>& impl)
        : BpInterface<IRexPlayerService>(impl)
    {
        ALOGD("create BpRexPlayerService \n");
    }

    virtual void addSampleData(uint32_t value)
    {
        ALOGE("BpRexPlayerService: addSampleData:%d \n",value);
    }
};

IMPLEMENT_META_INTERFACE(RexPlayerService,"android.rex.IRexPlayerService");


// ----------------------------------------------------------------------
status_t BnRexPlayerService::onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags)
{
    // ALOGE("out_buf hash is %u\n",hash32(data.data(),data.dataSize(),0xa5b35705));
    
    ALOGE("[binder_debug] BnRexPlayerService::onTransact, code: %d",code);

    // ALOGE("BnInterface: onTransact,will set __afl_area_ptr ");
    memset(__afl_area_ptr, 0, MAP_SIZE);
    __afl_area_ptr[0]=12;

    ALOGD("[BnRexPlayerService::onTransact] before __afl_area_ptr address %p", __afl_area_ptr);

    // map ashmem to __afl_area_ptr and unmap
    if (hssl::WpService::onTransact(code, data, reply) == android::NO_ERROR) {
        return android::NO_ERROR;
    }

    ALOGD("[BnRexPlayerService::onTransact] after __afl_area_ptr address %p", __afl_area_ptr);

    // const unsigned char* in_buf = data.data();
    // for (int i=0;i<data.dataSize();i++){
    //         ALOGE("in_buf[%d] 0x%x ",i,in_buf[i]);
    // }


    ALOGE("BnInterface: onTransact, code = %d ", code);
    switch (code)
    {
    case CODE1:
    {   

        CHECK_INTERFACE(IRexPlayerService, data, reply);
        int32_t data1 = data.readInt32();
        
        ALOGE("DATA-1 = %x",data1);

        ALOGE("CODE1 = %x, DATA = %x", CODE1,data1);
        int32_t data2 = data.readInt32();
        if (data2==1){
            ALOGE("DATA-2 = 1");
        }
        else if(data2==2){
            ALOGE("DATA-3 = 2");
        }
        else{
            ALOGE("DATA-4 = %x",data2);
        }
        break;
        
    } 
    case CODE2:
    {
        ALOGE("CODE2 = %x, data = %x", CODE2,data.readInt32());
        break;
    }
    case CODE3:
    {
        ALOGE("CODE3 = %x, data = %x", CODE3,data.readInt32());
        break;
    }
    case CODE4:
    {
        ALOGE("CODE4 = %x, data = %x", CODE4,data.readInt32());
        break;
    }
    case CODE5:
    {
        ALOGE("CODE5 = %x, data = %x", CODE5,data.readInt32());
        break;
    }

    default:
        return BBinder::onTransact(code, data, reply, flags);
        break;
    };

    return NO_ERROR;
}

};  //namespace android
