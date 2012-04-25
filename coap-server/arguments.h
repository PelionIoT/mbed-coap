#include "inttypes.h"

#define FALSE 0
#define TRUE 1

#define NONE   0
#define CLIENT 1
#define SERVER 2
#define DTLS_SERVER 3

#define MAX_OPTIONS 10

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

uint8_t arg_mode,arg_ack,arg_method,arg_content_type,arg_code,arg_hdr_type,arg_dtls,arg_gui;
uint16_t arg_tid;
uint8_t option_count, option_type[MAX_OPTIONS]; /*count the number of options as user inputs*/

char arg_dst[64];
uint16_t arg_port, arg_sport, arg_dport, arg_dtlsport;	//0-65535
unsigned char *arg_uri_path, *arg_payload, *st;




