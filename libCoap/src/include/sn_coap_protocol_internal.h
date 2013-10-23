/**
 * \file sn_coap_protocol_internal.h
 *
 * \brief Header file for CoAP Protocol part
 *
 *  Created on: Jun 30, 2011
 *      Author: tero
 *
 * \note Supports draft-ietf-core-coap-18
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SN_COAP_PROTOCOL_INTERNAL_H_
#define SN_COAP_PROTOCOL_INTERNAL_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

/* Maximum time in seconds of messages to be stored for Acknowledging. This time tells */
/* how long time User of CoAP C-library have time to send Piggy-backed acknowledgement */
/* message to Request sender. */
#define SN_COAP_ACK_INFO_MAX_TIME_MSGS_STORED    	20
#define SN_COAP_ACK_INFO_MAX_COUNT_MESSAGES_SAVED   10

/* * For Message resending * */

/* Init value for maximum count of ongoing active resending messages 										*/
/* This value depends on available memory: If there is restricted count of memory, use little value e.g. 1 	*/
/* Setting of this value to 0 will disable re-sending and also reduce use of ROM memory						*/
#define SN_COAP_RESENDING_MAX_COUNT		            0
/* Default value for re-sending buffer size */
#define SN_COAP_RESENDING_BUFFER_MAX_SIZE           0

/* These parameters sets maximum values application can set with API */
#define SN_COAP_MAX_ALLOWED_RESENDING_COUNT 		6 /**< Maximum allowed count of re-sending */
#define SN_COAP_MAX_ALLOWED_RESENDING_BUFF_SIZE 	6 /**< Maximum allowed number of saved re-sending messages */

/* * For Message duplication detecting * */

/* Init value for the maximum count of messages to be stored for duplication detection 			*/
/* Setting of this value to 0 will disable duplication check, also reduce use of ROM memory	 	*/
#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT          	0
/* Maximum allowed number of saved messages for duplicate searching */
#define SN_COAP_MAX_ALLOWED_DUPLICATION_MESSAGE_COUNT 	6

/* Maximum time in seconds of messages to be stored for duplication detection */
#define SN_COAP_DUPLICATION_MAX_TIME_MSGS_STORED    60 /* RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR * (2 ^ MAX_RETRANSMIT - 1) + the expected maximum round trip time */

/* * For Message blockwising * */

/* Init value for the maximum payload size to be sent and received at one blockwise message 						*/
/* Setting of this value to 0 will disable this feature, and also reduce use of ROM memory							*/
/* Note: Current Coap implementation supports Blockwise transfers specification version draft-ietf-core-block-03 	*/
/* Note: This define is common for both received and sent Blockwise messages 										*/
#ifndef SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
#define SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE 			0 /**< Must be 2^x and x is at least 4. Suitable values: 0, 16, 32, 64, 128, 256, 512 and 1024 */
#endif


#ifndef SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED
#define SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED      10 /**< Maximum time in seconds of data (messages and payload) to be stored for blockwising */
#endif

/* CoAP Resending defines */
#define DEFAULT_RESPONSE_TIMEOUT	10   /* Initial resending timeout as seconds, value is specified in IETF CoAP specification */
#define RESPONSE_RANDOM_FACTOR  	1   /* Resending random factor, value is specified in IETF CoAP specification */

/* * * * * * * * * * * * * * */
/* * * * ENUMERATIONS  * * * */
/* * * * * * * * * * * * * * */

/* * * * * * * * * * * * * */
/* * * * STRUCTURES  * * * */
/* * * * * * * * * * * * * */


/* Structure which is stored to Linked list for message sending purposes */
typedef struct coap_send_msg_
{
    uint8_t             resending_counter;  /* Tells how many times message is still tried to resend */
    uint32_t            resending_time;     /* Tells next resending time */

    sn_nsdl_transmit_s *send_msg_ptr;
} coap_send_msg_s;

/* Structure which is stored to Linked list for message acknowledgement purposes */
typedef struct coap_ack_info_
{
    uint32_t            timestamp; /* Tells when duplication information is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            msg_id;

    uint8_t             token_len;
    uint8_t            *token_ptr;
} coap_ack_info_s;

/* Structure which is stored to Linked list for message duplication detection purposes */
typedef struct coap_duplication_info_
{
    uint32_t            timestamp; /* Tells when duplication information is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            msg_id;
} coap_duplication_info_s;

/* Structure which is stored to Linked list for blockwise messages sending purposes */
typedef struct coap_blockwise_msg_
{
    uint32_t            timestamp;  /* Tells when Blockwise message is stored to Linked list */

    sn_coap_hdr_s		*coap_msg_ptr;
} coap_blockwise_msg_s;

/* Structure which is stored to Linked list for blockwise messages receiving purposes */
typedef struct coap_blockwise_payload_
{
    uint32_t            timestamp; /* Tells when Payload is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            payload_len;
    uint8_t            *payload_ptr;
} coap_blockwise_payload_s;

/**
 * \brief Releases any memory allocated in sn_nsdl_transmit_s
 */
extern void           sn_coap_builder_release_allocated_send_msg_mem(sn_nsdl_transmit_s *freed_send_msg_ptr);

#endif /* SN_COAP_PROTOCOL_INTERNAL_H_ */

#ifdef __cplusplus
}
#endif
