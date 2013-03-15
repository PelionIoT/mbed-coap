#ifndef _PL_TYPES_
#define _PL_TYPES_
#ifdef CC8051_PLAT

#define PL_LARGE __xdata
#define PL_PROGMEM __code
#define PL_REENTRANT __reentrant
#define NEAR_FUNC __near_func
#else

#define PL_LARGE
#define PL_REENTRANT
#define NEAR_FUNC
#define PL_PROGMEM
#endif

#ifndef NULL
#define NULL 0
#endif

/* Generic PART  to All platforms */
typedef signed char 		int8_t;
typedef signed short int    int16_t;

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;



#ifdef CC8051_PLAT

typedef unsigned long int uint32_t;
typedef signed long int int32_t;

typedef __xdata unsigned char UINT8_T;
typedef __xdata signed char INT8_T;

typedef __xdata unsigned short int UINT16_T;
typedef __xdata signed short int INT16_T;

typedef __xdata unsigned long int UINT32_T;
typedef __xdata signed long int INT32_T;

typedef __code const unsigned char prog_uint8_t;
typedef __code signed char prog_int8_t;

typedef __code unsigned short int prog_uint16_t;
typedef __code signed short int prog_int16_t;

typedef __code unsigned long int prog_uint32_t;
typedef __code signed long int prog_int32_t;

#elif x86
typedef  unsigned long int        uint32_t;
typedef  unsigned char const prog_uint8_t;
typedef  signed char prog_int8_t;

typedef  unsigned short int prog_uint16_t;
typedef  signed short int prog_int16_t;

typedef  unsigned long int prog_uint32_t;
typedef  signed long int prog_int32_t;
#else

#ifndef ATXMEGA256
#define __code
typedef signed long int          int32_t;
typedef unsigned long int        uint32_t;

typedef  unsigned char const prog_uint8_t;
typedef  signed char prog_int8_t;

typedef  unsigned short int prog_uint16_t;
typedef  signed short int prog_int16_t;

typedef  unsigned long int prog_uint32_t;
typedef  signed long int prog_int32_t;
//typedef unsigned long long uint64_t;
//typedef signed long long int64_t;
#else

#define __code

typedef unsigned long int uint32_t;
typedef signed long int int32_t;

typedef  unsigned char const prog_uint8_t;
typedef  signed char prog_int8_t;

typedef  unsigned short int prog_uint16_t;
typedef  signed short int prog_int16_t;

typedef  unsigned long int prog_uint32_t;
typedef  signed long int prog_int32_t;

#endif
#endif

//#define printf(x,y)
#endif /*_PL_TYPES_*/


#ifndef _NSDL_TYPES_
#define _NSDL_TYPES_


/* GRS specific declarations */

#define SN_MEM_ATTR_GRS_FUNC							/* Memory attribute for CoAP Protocol functions,    e.g: __root */
#define SN_MEM_ATTR_GRS_DECL				PL_LARGE	/* Memory attribute for CoAP Protocol declarations, e.g: PL_LARGE */

/* CoAP specific declarations */

#define SN_MEM_ATTR_COAP_PROTOCOL_FUNC                  /* Memory attribute for CoAP Protocol functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_PROTOCOL_DECL      PL_LARGE    /* Memory attribute for CoAP Protocol declarations, e.g: PL_LARGE */

#define SN_MEM_ATTR_COAP_BUILDER_FUNC                   /* Memory attribute for CoAP Builder functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_BUILDER_DECL       PL_LARGE    /* Memory attribute for CoAP builder declarations, e.g: PL_LARGE */

#define SN_MEM_ATTR_COAP_PARSER_FUNC                    /* Memory attribute for CoAP Parser functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_PARSER_DECL        PL_LARGE    /* Memory attribute for CoAP Parser declarations, e.g: PL_LARGE */

#define SN_MEM_ATTR_COAP_VALID_CHECK_FUNC               /* Memory attribute for CoAP Validity Check functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_VALID_CHECK_DECL   PL_LARGE    /* Memory attribute for CoAP Validity Check declarations, e.g: PL_LARGE */

/* Linked list specific declarations */

#define SN_LINKED_LIST_FUNCTION_POINTER_MEMORY_ATTRIBUTE
#define SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE

/* HTTP specific declarations */
#define SN_HTTP_CONST_ARRAY_MEMORY_ATTRIBUTE const PL_PROGMEM
#define SN_HTTP_FUNCTION_POINTER_MEMORY_ATTRIBUTE
#define SN_HTTP_FUNCTION_MEMORY_ATTRIBUTE

#endif /*_NSDL_TYPES_*/
