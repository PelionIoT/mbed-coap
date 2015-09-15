
#ifndef __SN_NSDL_STUB_H__
#define __SN_NSDL_STUB_H__

typedef struct {
    int8_t expectedInt8;
    uint16_t expectedUint16;
    bool allocatePayloadPtr;
}sn_nsdl_stub_def;

extern sn_nsdl_stub_def sn_nsdl_stub;

#endif //__SN_NSDL_STUB_H__
