/*
 * Copyright (c) 2011-2015 ARM. All rights reserved.
 */

/**
 * \file sn_coap_builder.c
 *
 * \brief CoAP Message builder
 *
 * Functionality: Builds CoAP message
 *
 */

/* * * * * * * * * * * * * * */
/* * * * INCLUDE FILES * * * */
/* * * * * * * * * * * * * * */

#include <string.h> /* For memset() and memcpy() */

#include "ns_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_header_internal.h"
#include "sn_coap_protocol_internal.h"

/* * * * LOCAL FUNCTION PROTOTYPES * * * */
static int8_t   sn_coap_builder_header_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);
static int8_t   sn_coap_builder_options_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);
static uint16_t sn_coap_builder_options_calc_option_size(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option);
static int16_t  sn_coap_builder_options_build_add_one_option(uint8_t **dst_packet_data_pptr, uint16_t option_len, uint8_t *option_ptr, sn_coap_option_numbers_e option_number);
static int16_t  sn_coap_builder_options_build_add_zero_length_option(uint8_t **dst_packet_data_pptr, uint8_t option_length, uint8_t option_exist, sn_coap_option_numbers_e option_number);
static int16_t 	sn_coap_builder_options_build_add_multiple_option(uint8_t **dst_packet_data_pptr, uint8_t **src_pptr, uint16_t *src_len_ptr, sn_coap_option_numbers_e option);
static uint8_t 	sn_coap_builder_options_get_option_part_count(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option);
static uint16_t sn_coap_builder_options_get_option_part_length_from_whole_option_string(uint16_t query_len, uint8_t *query_ptr, uint8_t query_index, sn_coap_option_numbers_e option);
static int16_t 	sn_coap_builder_options_get_option_part_position(uint16_t query_len, uint8_t *query_ptr, uint8_t query_index, sn_coap_option_numbers_e option);
static void     sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);
static uint8_t 	sn_coap_builder_options_calculate_jump_need(sn_coap_hdr_s *src_coap_msg_ptr, uint8_t block_option);

/* * * * GLOBAL DECLARATIONS * * * */
static uint16_t global_previous_option_number = 0;    	/* Previous Option number in CoAP message */

/* * * * EXTERN VARIABLES * * * */
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
extern uint16_t 	sn_coap_block_data_size; 				/* From sn_coap_protocol_ieft_draft_12.c */
#endif

sn_coap_hdr_s *sn_coap_build_response(struct coap_s *handle, sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code)
{
}

int16_t sn_coap_builder(uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr)
{
}

uint16_t sn_coap_builder_calc_needed_packet_data_size(sn_coap_hdr_s *src_coap_msg_ptr)
{
}

/**
 * \fn static uint8_t sn_coap_builder_options_calculate_jump_need(sn_coap_hdr_s *src_coap_msg_ptr, uint8_t block_option)
 *
 * \brief Checks if there is need for option jump
 *
 * \param  *src_coap_msg_ptr is source of checked CoAP message
 *
 * \param  block option marks if block option is to be added to message later. 0 = no block option, 1 = block1 and 2 = block2
 *
 * \return Returns bytes needed for jumping
 */

static uint8_t sn_coap_builder_options_calculate_jump_need(sn_coap_hdr_s *src_coap_msg_ptr, uint8_t block_option)
{
}

/**
 * \fn static int8_t sn_coap_builder_header_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Builds Header part of Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 *
 * \return Return value is 0 in ok case and -1 in failure case
 **************************************************************************** */
static int8_t sn_coap_builder_header_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
{
}

/**
 * \fn static int8_t sn_coap_builder_options_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Builds Options part of Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 *
 * \return Return value is 0 in ok case and -1 in failure case
 */
static int8_t sn_coap_builder_options_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
{
}

/**
 * \fn static int16_t sn_coap_builder_options_build_add_one_option(uint8_t **dst_packet_data_pptr, uint16_t option_value_len, uint8_t *option_value_ptr, sn_coap_option_numbers_e option_number)
 *
 * \brief Adds Options part of Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param option_value_len is Option value length to be added
 *
 * \param *option_value_ptr is pointer to Option value data to be added
 *
 * \param option_number is Option number to be added
 *
 * \return Return value is 0 if option was not added, 1 if added and -1 in failure case
 */
static int16_t sn_coap_builder_options_build_add_one_option(uint8_t **dst_packet_data_pptr, uint16_t option_len,
                                                            uint8_t *option_ptr, sn_coap_option_numbers_e option_number)
{
}

int16_t sn_coap_builder_options_build_add_zero_length_option(uint8_t **dst_packet_data_pptr, uint8_t option_length, uint8_t option_exist, sn_coap_option_numbers_e option_number)
{
}

/**
 * \fn static int16_t sn_coap_builder_options_build_add_multiple_option(uint8_t **dst_packet_data_pptr, uint8_t **src_pptr, uint16_t *src_len_ptr, sn_coap_option_numbers_e option)
 *
 * \brief Builds Option Uri-Query from given CoAP Header structure to Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param uint8_t **src_pptr
 *
 *  \param uint16_t *src_len_ptr
 *
 *  \paramsn_coap_option_numbers_e option option to be added
 *
 * \return Return value is 0 in ok case and -1 in failure case
 */
static int16_t sn_coap_builder_options_build_add_multiple_option(uint8_t **dst_packet_data_pptr, uint8_t **src_pptr, uint16_t *src_len_ptr, sn_coap_option_numbers_e option)
{
}


/**
 * \fn static uint16_t sn_coap_builder_options_calc_option_size(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
 *
 * \brief Calculates needed Packet data memory size for option
 *
 * \param path_len is length of calculated strting(s)
 *
 * \param *path_ptr is pointer to calculated options
 *
 * \return Return value is count of needed memory as bytes for Uri-query option
 */
static uint16_t sn_coap_builder_options_calc_option_size(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
{
}



/**
 * \fn static uint8_t sn_coap_builder_options_get_option_part_count(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
 *
 * \brief Gets query part count from whole option string
 *
 * \param query_len is length of whole Path
 *
 * \param *query_ptr is pointer to the start of whole Path
 *
 * \return Return value is count of query parts
 */
static uint8_t sn_coap_builder_options_get_option_part_count(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
{
}

/**
 * \fn static uint16_t sn_coap_builder_options_get_option_part_length_from_whole_option_string(uint16_t query_len,
                                                                             uint8_t *query_ptr,
                                                                             uint8_t query_index, sn_coap_option_numbers_e option)
 *
 * \brief Gets one's query part length from whole query string
 *
 * \param query_len is length of whole string
 *
 * \param *query_ptr is pointer to the start of whole string
 *
 * \param query_index is query part index to be found
 *
 * \param sn_coap_option_numbers_e option is option number of the option
 *
 * \return Return value is length of query part
 */
static uint16_t sn_coap_builder_options_get_option_part_length_from_whole_option_string(uint16_t query_len, uint8_t *query_ptr,
																						uint8_t query_index, sn_coap_option_numbers_e option)
{
}

/**
 * \fn static uint16_t sn_coap_builder_options_get_option_part_position(uint16_t query_len,
                                                               uint8_t *query_ptr,
                                                               uint8_t query_index, sn_coap_option_numbers_e option)
 *
 * \brief Gets query part position in whole query
 *
 * \param query_len is length of whole query
 *
 * \param *query_ptr is pointer to the start of whole query
 *
 * \param query_index is query part index to be found
 *
 * \return Return value is position (= offset) of query part in whole query. In
 *         fail cases -1 is returned.
 */
static int16_t sn_coap_builder_options_get_option_part_position(uint16_t query_len, uint8_t *query_ptr,
                                                               uint8_t query_index, sn_coap_option_numbers_e option)
{
}


/**
 * \fn static void sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Builds Options part of Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 */
static void sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
{
}
