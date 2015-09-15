
#ifndef __SN_GRS_STUB_H__
#define __SN_GRS_STUB_H__

#include "sn_nsdl_lib.h"
#include "sn_grs.h"

typedef struct {
    bool retNull;
    int8_t infoRetCounter;
    int8_t info2ndRetCounter;
    int8_t expectedInt8;
    int8_t int8SuccessCounter;
    struct grs_s *expectedGrs;
    sn_nsdl_resource_info_s *expectedInfo;
    sn_grs_resource_list_s *expectedList;

    bool useMockedPath;
    uint8_t mockedPath[8];
    uint8_t mockedPathLen;
}sn_grs_stub_def;

extern sn_grs_stub_def sn_grs_stub;

#endif //__SN_GRS_STUB_H__
