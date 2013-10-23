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


/* * * * * * * * * * * * * * * * * * * * * * */
/* * * * EXTERNAL FUNCTION PROTOTYPES  * * * */
/* * * * * * * * * * * * * * * * * * * * * * */

/**
 * \brief This function sets the memory allocation and deallocation functions and used TX callback function pointer the library will use, and must be called first.
 */
extern int8_t 			   sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
										uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *));

/**
 * \brief Frees all allocated memory in libCoap protocol part.
 */
extern int8_t 			   sn_coap_protocol_destroy(void);

/**
 * \brief Use to build an outgoing message buffer from a CoAP header structure.
 */
extern int16_t             sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr, uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr);

/**
 * \brief Use to parse an incoming message buffer to a CoAP header structure.
 */
extern sn_coap_hdr_s      *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);

/**
 * \brief Called periodically to allow the protocol to update retransmission timers and destroy unneeded data.
 */
extern int8_t 			   sn_coap_protocol_exec(uint32_t current_time);

/**
 * \brief If block transfer is enabled, this function changes the block size.
 */
extern int8_t 			   sn_coap_protocol_set_block_size(uint16_t block_size);

/**
 * \brief If dublicate message detection is enabled, this function changes buffer size.
 */
extern int8_t 			   sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count);

/**
 * \brief If re-transmissions are enabled, this function changes resending count and buffer size.
 */
extern int8_t 			   sn_coap_protocol_set_retransmission(uint8_t resending_count, uint8_t buffer_size, uint8_t resending_intervall);

/* NSP manual registration functions */

/**
 * \brief Create an NSP registration message.
 */
extern int8_t 			   sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr);

/**
 * \brief Create an NSP update message.
 */
extern int8_t 			   sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

/**
 * \brief Create an NSP de-registration message.
 */
extern int8_t 			   sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

#endif /* SN_COAP_PROTOCOL_H_ */

#ifdef __cplusplus
}
#endif
