/**
 * \file sn_coap_protocol.h
 *
 * \brief CoAP C-library User protocol interface header file
 *
 *  Created on: Jun 30, 2011
 *      Author: tero
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SN_COAP_PROTOCOL_H_
#define SN_COAP_PROTOCOL_H_

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
#define SN_COAP_RESENDING_BUFFER_MAX_SIZE           1

/* These parameters sets maximum values application can set with API */
/* Maximum allowed count of re-sending */
#define SN_COAP_MAX_ALLOWED_RESENDING_COUNT 		6
/* Maximum allowed number of saved re-sending messages */
#define SN_COAP_MAX_ALLOWED_RESENDING_BUFF_SIZE 	6

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
#define SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE 			0 /* Must be 2^x and x is at least 4. Suitable values: 0, 16, 32, 64, 128, 256, 512 and 1024 */
#endif


/* Maximum time in seconds of data (messages and payload) to be stored for blockwising */
#ifndef SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED
#define SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED      10
#endif


/* * * * * * * * * * * * * * * * * * * * * * */
/* * * * EXTERNAL FUNCTION PROTOTYPES  * * * */
/* * * * * * * * * * * * * * * * * * * * * * */

extern int8_t 			   sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
										uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *));
extern int8_t 			   sn_coap_protocol_destroy(void);
extern int16_t             sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr, uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr);
extern sn_coap_hdr_s      *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);
extern int8_t 			   sn_coap_protocol_exec(uint32_t current_time);
extern int8_t 			   sn_coap_protocol_set_block_size(uint16_t block_size);
extern int8_t 			   sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count);
extern int8_t 			   sn_coap_protocol_set_retransmission(uint8_t resending_count, uint8_t buffer_size);

/* NSP registration functions */
extern int8_t 			   sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr);
extern int8_t 			   sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);
extern int8_t 			   sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

#endif /* SN_COAP_PROTOCOL_H_ */

#ifdef __cplusplus
}
#endif
