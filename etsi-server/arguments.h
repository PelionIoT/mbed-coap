#include "inttypes.h"

#define FALSE 0
#define TRUE 1

#ifdef MACOSX 
// ----------------------------------------
// Mac OS X
#ifdef __DARWIN_UNIX03
typedef unsigned short port_t;
#else
#include <mach/port.h>
#endif // __DARWIN_UNIX03
typedef unsigned long ipaddr_t;
#endif

uint8_t arg_dtls,arg_gui;
uint16_t arg_port, arg_sport, arg_dport, arg_dtlsport;	//0-65535
char arg_dst[64];



