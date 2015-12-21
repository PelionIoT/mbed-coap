/**
 * \file 	arguments.h
 *
 * \brief	Arguments for command line parameters
 *
 * \author 	Zach Shelby <zach@sensinode.com>
 *
 */

#ifndef _ARGUMENTS_
#define _ARGUMENTS_
#include "resource_generation_help.h"

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

/* Argument variables */
uint16_t arg_port, arg_sport, arg_dport;	//0-65535
char arg_dst[64];

#endif /* _ARGUMENTS_ */


