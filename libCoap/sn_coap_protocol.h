/******************************************************************************
 * \file sn_coap_protocol.h
 *
 * \brief CoAP C-library User protocol interface header file
 *
 *  Created on: Jun 30, 2011
 *      Author: pekka_ext
 *
 *****************************************************************************/

#ifndef SN_COAP_PROTOCOL_H_
#define SN_COAP_PROTOCOL_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

/* Maximum time in seconds of messages to be stored for Acknowledging. This time tells */
/* how long time User of CoAP C-library have time to send Piggy-backed acknowledgement */
/* message to Request sender. */
#define SN_COAP_ACK_INFO_MAX_TIME_MSGS_STORED    10

/* * * * * * * * * * * * * * * * * * * * * * */
/* * * * EXTERNAL FUNCTION PROTOTYPES  * * * */
/* * * * * * * * * * * * * * * * * * * * * * */

extern int8_t 			   sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
										uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *));
extern int8_t 			   sn_coap_protocol_destroy(void);
extern int16_t             sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr, uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr);
extern sn_coap_hdr_s      *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);
extern sn_nsdl_transmit_s *sn_coap_protocol_exec(uint32_t current_time);

/* NSP registration functions */
extern int8_t 			   sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr);
extern int8_t 			   sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);
extern int8_t 			   sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

#endif /* SN_COAP_PROTOCOL_H_ */
