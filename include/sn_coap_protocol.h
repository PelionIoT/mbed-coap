/**
 * \file sn_coap_protocol.h
 *
 * \brief CoAP C-library User protocol interface header file
 *
 * Copyright © 2011 - 2014, ARM Limited or its affiliates. All rights reserved.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SN_COAP_PROTOCOL_H_
#define SN_COAP_PROTOCOL_H_

/**
 * \fn int8_t sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
		uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
		int8_t (*used_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *)
 *
 * \brief Initializes CoAP Protocol part. When using libNsdl, sn_nsdl_init() calls this function.
 *
 * \param *used_malloc_func_ptr is function pointer for used memory allocation function.
 *
 * \param *used_free_func_ptr is function pointer for used memory free function.
 *
 * \param *used_tx_callback_ptr function callback pointer to tx function for sending coap messages
 *
 * \param *used_rx_callback_ptr used to return CoAP header struct with status COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED
 * 		  when re-sendings exceeded. If set to NULL, no error message is returned.
 *
 * \return 	0 if success
 * 			-1 if failed
 */

extern 	int8_t sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
										uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
										int8_t (*used_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *));

/**
 * \fn int8_t sn_coap_protocol_destroy(void)
 *
 * \brief Frees all memory from CoAP protocol part
 *
 * \return Return value is always 0
 */
extern int8_t 			   sn_coap_protocol_destroy(void);

/**
 * \fn int16_t sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr, uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Builds Packet data from given CoAP header structure to be sent
 *
 * \param *dst_addr_ptr is pointer to destination address where CoAP message
 *        will be sent (CoAP builder needs that information for message resending purposes)
 *
 * \param *dst_packet_data_ptr is pointer to destination of built Packet data
 *
 * \param *src_coap_msg_ptr is pointer to source of built Packet data
 *
 * \return Return value is byte count of built Packet data.\n
 *         Note: If message is blockwised, all payload is not sent at the same time\n
 *         In failure cases:\n
 *          -1 = Failure in CoAP header structure\n
 *          -2 = Failure in given pointer (= NULL)\n
 *          -3 = Failure in Reset message\ŋ
 *         If there is not enough memory (or User given limit exceeded) for storing
 *         resending messages, situation is ignored.
 */
extern int16_t             sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr, uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr);

/**
 * \fn sn_coap_hdr_s *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
 *
 * \brief Parses received CoAP message from given Packet data
 *
 * \param *src_addr_ptr is pointer to source address of received CoAP message
 *        (CoAP parser needs that information for Message acknowledgement)
 *
 * \param packet_data_len is length of given Packet data to be parsed to CoAP message
 *
 * \param *packet_data_ptr is pointer to source of Packet data to be parsed to CoAP message
 *
 * \return Return value is pointer to parsed CoAP message structure. This structure includes also coap_status field.\n
 *         In following failure cases NULL is returned:\n
 *          -Given NULL pointer\n
 *          -Failure in parsed header of non-confirmable message\ŋ
 *          -Out of memory (malloc() returns NULL)
 */
extern sn_coap_hdr_s      *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);

/**
 * \fn int8_t sn_coap_protocol_exec(uint32_t current_time)
 *
 * \brief Sends CoAP messages from re-sending queue, if there is any.
 * 		  Cleans also old messages from the duplication list and from block receiving list
 *
 *        This function can be called e.g. once in a second but also more frequently.
 *
 * \param current_time is System time in seconds. This time is
 *        used for message re-sending timing and to identify old saved data.
 *
 * \return 	0 if success
 * 			-1 if failed
 */

extern int8_t 			   sn_coap_protocol_exec(uint32_t current_time);

/**
 * \fn int8_t sn_coap_protocol_set_block_size(uint16_t block_size)
 *
 * \brief If block transfer is enabled, this function changes the block size.
 *
 * \param uint16_t block_size maximum size of CoAP payload. Valid sizes are 16, 32, 64, 128, 256, 512 and 1024 bytes
 * \return 	0 = success
 * 			-1 = failure
 */
extern int8_t 			   sn_coap_protocol_set_block_size(uint16_t block_size);

/**
 * \fn int8_t sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count)
 *
 * \brief If dublicate message detection is enabled, this function changes buffer size.
 *
 * \param uint8_t message_count max number of messages saved for duplicate control
 * \return 	0 = success
 * 			-1 = failure
 */
extern int8_t 			   sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count);

/**
 * \fn int8_t sn_coap_protocol_set_retransmission_parameters(uint8_t resending_count, uint8_t resending_intervall)
 *
 * \brief  If re-transmissions are enabled, this function changes resending count and interval.
 *
 * \param uint8_t resending_count max number of resendings for message
 * \param uint8_t resending_intervall message resending intervall in seconds
 * \return 	0 = success
 * 			-1 = failure
 */
extern int8_t 			   sn_coap_protocol_set_retransmission_parameters(uint8_t resending_count, uint8_t resending_interval);

/**
 * \fn int8_t sn_coap_protocol_set_retransmission_buffer(uint8_t buffer_size_messages, uint16_t buffer_size_bytes)
 *
 * \brief If re-transmissions are enabled, this function changes message retransmission queue size.
 *  Set size to '0' to disable feature. If both are set to '0', then re-sendings are disabled.
 *
 * \param uint8_t buffer_size_messages queue size - maximum number of messages to be saved to queue
 * \param uint8_t buffer_size_bytes queue size - maximum size of messages saved to queue
 * \return 	0 = success
 * 			-1 = failure
 */
extern int8_t			   sn_coap_protocol_set_retransmission_buffer(uint8_t buffer_size_messages, uint16_t buffer_size_bytes);

/**
 * \fn void sn_coap_protocol_clear_retransmission_buffer(void)
 *
 * \brief If re-transmissions are enabled, this function removes all messages from the retransmission queue.
 */
extern void 			   sn_coap_protocol_clear_retransmission_buffer(void);


/* * * Manual registration functions * * */


/**
 * \fn int8_t sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr)
 *
 * \brief Builds RD registration request packet
 *
 * \param *coap_hdr_ptr is destination for built Packet data
 * \param *endpoint_info_ptr pointer to struct that contains endpoint info parameters
 *
 * \return Return value 0 given on success. In failure cases:\n
 *          -1 = Failure
 */
extern int8_t 			   sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr);

/**
 * \fn int8_t sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length)
 *
 * \brief Builds RD update request packet
 *
 * \param *coap_hdr_ptr is destination for built Packet data
 * \param *location The location returned when registering with the RD
 * \param length length of the location
 *
 * \return Return value 0 given on success. In failure cases:\n
 *          -1 = Failure
 */
extern int8_t 			   sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

/**
 * \fn int8_t sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length)
 *
 * \brief Builds RD de-registrtion request packet
 *
 * \param *coap_hdr_ptr is destination for built Packet data
 * \param *location The location returned when registering with the RD
 * \param length length of the location
 *
 * \return Return value 0 given on success. In failure cases:\n
 *          -1 = Failure
 */
extern int8_t 			   sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length);

#endif /* SN_COAP_PROTOCOL_H_ */

#ifdef __cplusplus
}
#endif
