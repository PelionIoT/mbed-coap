#ifndef _PL_PC_TYPES_
#define _PL_PC_TYPES_

//#include <inttypes.h>

#define pl_int_disable() ;
#define pl_int_enable() ;

#define PL_LARGE
#define PL_REENTRANT
#define NEAR_FUNC
#define PL_PROGMEM

#ifndef NULL
#define NULL 0
#endif

// TODO: PeKa added 17-8-2011
typedef signed short int    int16_t;
typedef signed int          int32_t;
typedef unsigned int        uint32_t;

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;

typedef  unsigned char prog_uint8_t;
typedef  signed char prog_int8_t;

typedef  unsigned short int prog_uint16_t;
typedef  signed short int prog_int16_t;

typedef  unsigned long int prog_uint32_t;
typedef  signed long int prog_int32_t;

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
#define SN_HTTP_CONST_ARRAY_MEMORY_ATTRIBUTE
#define SN_HTTP_FUNCTION_POINTER_MEMORY_ATTRIBUTE
#define SN_HTTP_FUNCTION_MEMORY_ATTRIBUTE

#endif /*_PL_PC_TYPES_*/

