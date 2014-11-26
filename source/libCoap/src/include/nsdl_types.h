#ifndef _NSDL_TYPES_
#define _NSDL_TYPES_

#include "ns_types.h"

/* GRS specific declarations */

#define SN_MEM_ATTR_GRS_FUNC							/* Memory attribute for CoAP Protocol functions,    e.g: __root */
#define SN_MEM_ATTR_GRS_DECL				NS_LARGE	/* Memory attribute for CoAP Protocol declarations, e.g: NS_LARGE */

/* CoAP specific declarations */

#define SN_MEM_ATTR_COAP_PROTOCOL_FUNC                  /* Memory attribute for CoAP Protocol functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_PROTOCOL_DECL      NS_LARGE    /* Memory attribute for CoAP Protocol declarations, e.g: NS_LARGE */

#define SN_MEM_ATTR_COAP_BUILDER_FUNC                   /* Memory attribute for CoAP Builder functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_BUILDER_DECL       NS_LARGE    /* Memory attribute for CoAP builder declarations, e.g: NS_LARGE */

#define SN_MEM_ATTR_COAP_PARSER_FUNC                    /* Memory attribute for CoAP Parser functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_PARSER_DECL        NS_LARGE    /* Memory attribute for CoAP Parser declarations, e.g: NS_LARGE */

#define SN_MEM_ATTR_COAP_VALID_CHECK_FUNC               /* Memory attribute for CoAP Validity Check functions,    e.g: __root */
#define SN_MEM_ATTR_COAP_VALID_CHECK_DECL   NS_LARGE    /* Memory attribute for CoAP Validity Check declarations, e.g: NS_LARGE */

#endif /*_NSDL_TYPES_*/
