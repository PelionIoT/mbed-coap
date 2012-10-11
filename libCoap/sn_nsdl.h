/* ****************************************************************************
 * \file sn_nsdl.h
 *
 * \brief NanoService Devices Library generic header file
 *
 *  Created on: Aug 23, 2011
 *      Author: pekka_ext
 *
 * ***************************************************************************/

#ifndef SN_NSDL_H_
#define SN_NSDL_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

/* * * Common * * */

#define SN_NSDL_SUCCESS  0
#define SN_NSDL_FAILURE (-1)

/* * * CoAP specific * * */

/* * For Message resending * */

/* Maximum count of ongoing active resending messages */
/* This value depends on available memory: If there is restricted count of memory, use little value e.g. 1 */
/* Setting of this value to 0 will also reduce use of ROM memory */
#define SN_COAP_RESENDING_MAX_MSGS_COUNT            0

/* * For Message duplication detecting * */

/* Maximum count of messages to be stored for duplication detection */
/* Setting of this value to 0 will also reduce use of ROM memory */
#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT          0

/* Maximum time in seconds of messages to be stored for duplication detection */
#define SN_COAP_DUPLICATION_MAX_TIME_MSGS_STORED    60 /* RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR * (2 ^ MAX_RETRANSMIT - 1) + the expected maximum round trip time */

/* * For Message blockwising * */

/* Maximum payload size to be sent and received at one blockwise message */
/* Setting of this value to 0 will also reduce use of ROM memory */
/* Note: Current Coap implementation supports Blockwise transfers specification version draft-ietf-core-block-03 */
/* Note: This define is common for both received and sent Blockwise messages */
#ifndef SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
#define SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE          0 /* Must be 2^x and x is at least 4. Suitable values: 0, 16, 32, 64, 128, 256, 512 and 1024 */
#endif

/* Maximum time in seconds of data (messages and payload) to be stored for blockwising */
#ifndef SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED
#define SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED      120
#endif

/* * * * * * * * * * * * * * */
/* * * * ENUMERATIONS  * * * */
/* * * * * * * * * * * * * * */


typedef enum sn_nsdl_capab_
{
    SN_NSDL_PROTOCOL_HTTP           = 0x01,
    SN_NSDL_PROTOCOL_HTTPS          = 0x02,
    SN_NSDL_PROTOCOL_COAP           = 0x04
} sn_nsdl_capab_e;

typedef enum sn_nsdl_addr_type_
{
    SN_NSDL_ADDRESS_TYPE_IPV6       = 0x01,
    SN_NSDL_ADDRESS_TYPE_IPV4       = 0x02,
    SN_NSDL_ADDRESS_TYPE_HOSTNAME   = 0x03,
    SN_NSDL_ADDRESS_TYPE_NONE       = 0xFF
} sn_nsdl_addr_type_e;


#define SN_NDSL_RESOURCE_NOT_REGISTERED	0
#define SN_NDSL_RESOURCE_REGISTERING	1
#define SN_NDSL_RESOURCE_REGISTERED		2


/* * * * * * * * * * * * * */
/* * * * STRUCTURES  * * * */
/* * * * * * * * * * * * * */

/* Address structure of Packet data */
typedef struct sn_nsdl_addr_
{
    sn_nsdl_addr_type_e     type;

    uint8_t                 addr_len;
    uint8_t                *addr_ptr;

    uint16_t                port;

    void					*socket_information;

} sn_nsdl_addr_s;

/* This structure is returned by sn_coap_exec() for sending */
typedef struct sn_nsdl_transmit_
{
    sn_nsdl_addr_s         *dst_addr_ptr;

    sn_nsdl_capab_e         protocol;

    uint16_t                packet_len;
    uint8_t                *packet_ptr;
} sn_nsdl_transmit_s;


typedef struct sn_nsdl_resource_parameters_
{
	uint8_t		*resource_type_ptr;
	uint16_t	resource_type_len;

	uint8_t		*interface_description_ptr;
	uint16_t	interface_description_len;

	uint8_t		coap_content_type_len;
	uint8_t		*coap_content_type_ptr;

	uint8_t		mime_content_type;

	uint8_t		observable;

	uint8_t		registered;

}sn_nsdl_resource_parameters_s;


/* simple nsdl addons */
typedef struct registration_info_
{
	const uint8_t *endpoint_ptr;
	uint8_t endpoint_len;

	const uint8_t *endpoint_type_ptr;
	uint8_t endpoint_type_len;

	const uint8_t *links_ptr;
	uint16_t links_len;

}registration_info_t;


#endif /* SN_NSDL_H_ */
