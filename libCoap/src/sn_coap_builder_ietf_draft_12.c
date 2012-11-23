/**
 * \file sn_coap_builder_ietf_draft_12.c
 *
 * \brief CoAP Message builder
 *
 * Functionality: Builds CoAP messge
 *
 *  Created on: Jun 30, 2011
 *      Author: tero
 *
 * \note Supports draft-ietf-core-coap-12
 */

/* * * * * * * * * * * * * * */
/* * * * INCLUDE FILES * * * */
/* * * * * * * * * * * * * * */

#include <stdlib.h> /* For libary malloc() */
#include <string.h> /* For memset() and memcpy() */

#include "pl_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header_ietf_draft_12.h"
#include "sn_coap_protocol_ietf_draft_12.h"

/* * * * * * * * * * * * * * * * * * * * */
/* * * * LOCAL FUNCTION PROTOTYPES * * * */
/* * * * * * * * * * * * * * * * * * * * */

static int8_t   sn_coap_builder_header_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);
static int8_t   sn_coap_builder_options_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);
static uint16_t sn_coap_builder_options_calc_option_size(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option);
static int16_t  sn_coap_builder_options_build_add_one_option(uint8_t **dst_packet_data_pptr, uint16_t option_value_len, uint8_t *option_value_ptr, sn_coap_option_numbers_e option_number);
static int16_t 	sn_coap_builder_options_build_add_multiple_option(uint8_t **dst_packet_data_pptr, uint8_t **src_pptr, uint16_t *src_len_ptr, sn_coap_option_numbers_e option);
static int8_t   sn_coap_builder_options_increase_count_in_header(uint8_t increased_options_count);
static int16_t  sn_coap_builder_options_add_option_value_len(uint16_t option_value_len, uint8_t **dst_packet_data_pptr);
static uint8_t 	sn_coap_builder_options_get_option_part_count(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option);
static uint16_t sn_coap_builder_options_get_option_part_length_from_whole_option_string(uint16_t query_len, uint8_t *query_ptr, uint8_t query_index, sn_coap_option_numbers_e option);
static uint16_t sn_coap_builder_options_get_option_part_position(uint16_t query_len, uint8_t *query_ptr, uint8_t query_index, sn_coap_option_numbers_e option);

static void     sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr);

/* * * * * * * * * * * * * * * * * */
/* * * * GLOBAL DECLARATIONS * * * */
/* * * * * * * * * * * * * * * * * */

SN_MEM_ATTR_COAP_BUILDER_DECL static uint8_t *base_packet_data_ptr         = NULL; /* Base (= original) destination Packet data pointer value */
SN_MEM_ATTR_COAP_BUILDER_DECL static uint8_t global_previous_option_number = 0;    /* Previous Option number in CoAP message */

SN_MEM_ATTR_COAP_BUILDER_DECL void* (*sn_coap_malloc)(uint16_t); /* Function pointer for used malloc() function */
SN_MEM_ATTR_COAP_BUILDER_DECL void  (*sn_coap_free)(void*);      /* Function pointer for used free()   function */

/**
 * \fn void sn_coap_builder_and_parser_init(void* (*used_malloc_func_ptr)(uint16_t),
 * 											void (*used_free_func_ptr)(void*))
 *
 * \brief Initializes CoAP Builder and Parser parts
 *
 * \param void* used_malloc_func_ptr is function pointer for used free() function.
 *        If set to NULL, CoAP Builder and Parser parts use standard C-library free() function.
 *
 * \param void *used_free_func_ptr
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
void sn_coap_builder_and_parser_init(void* (*used_malloc_func_ptr)(uint16_t),
                                     void (*used_free_func_ptr)(void*))
{
    /* * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Handle malloc() and free() mapping  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * */

    /* * * Handling malloc() * * */
    sn_coap_malloc = used_malloc_func_ptr;


    /* * * Handling free() * * */
    sn_coap_free = used_free_func_ptr;
}

/**
 * \fn sn_coap_hdr_s *sn_coap_build_response(sn_coap_hdr_s *coap_packet_ptr)
 *
 * \brief Prepares generic response packet from a request packet. This function allocates memory for the resulting sn_coap_hdr_s
 *
 * \param *coap_packet_ptr The request packet pointer
 *
 * \return *coap_packet_ptr The allocated and pre-filled response packet pointer
 * 			NULL	Error in parsing the request
 *
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
sn_coap_hdr_s *sn_coap_build_response(sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code)
{
	sn_coap_hdr_s *coap_res_ptr;
	coap_res_ptr = sn_coap_malloc(sizeof(sn_coap_hdr_s));
	if(!coap_res_ptr)
		return NULL;

	memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));

	if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
	{
		coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
		coap_res_ptr->msg_code = msg_code;
		coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
	}

	else if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
	{
		coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
		coap_res_ptr->msg_code = msg_code;
		/* msg_id needs to be set by the caller in this case */
	}

	else
	{
		return NULL;
	}

	if (coap_packet_ptr->token_ptr)
	{
		coap_res_ptr->token_len = coap_packet_ptr->token_len;
		coap_res_ptr->token_ptr = sn_coap_malloc(coap_res_ptr->token_len);
		if(!coap_res_ptr->token_ptr)
		{
			sn_coap_free(coap_res_ptr);
			return NULL;
		}
		memcpy(coap_res_ptr->token_ptr, coap_packet_ptr->token_ptr, coap_res_ptr->token_len);
	}
	return coap_res_ptr;
}


/**
 * \fn int16_t sn_coap_builder(uint8_t *dst_packet_data_ptr,
 * 									sn_coap_hdr_s *src_coap_msg_ptr, uint16_t msg_id)
 *
 * \brief Builds Packet data from given CoAP header structure
 *
 * \param *dst_packet_data_ptr is destination for built Packet data
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 *
 * \return Return value is byte count of built Packet data. In failure cases:\n
 *          -1 = Failure in given CoAP header structure\n
 *          -2 = Failure in given pointer (= NULL)
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
int16_t sn_coap_builder(uint8_t *dst_packet_data_ptr,
                        sn_coap_hdr_s *src_coap_msg_ptr)
{
    int8_t ret_status = 0;

    /* * * * * * * * * * * * * * * * * * */
    /* * * * Check given pointers  * * * */
    /* * * * * * * * * * * * * * * * * * */

    if (dst_packet_data_ptr == NULL ||
        src_coap_msg_ptr == NULL)
    {
        /* Pointer checking failed */
        return -2;
    }
    else
    {
        /* Initialize given Packet data memory area with zero values */

        uint16_t dst_byte_count_to_be_built = sn_coap_builder_calc_needed_packet_data_size(src_coap_msg_ptr);

        memset(dst_packet_data_ptr, 0, dst_byte_count_to_be_built);
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Store base (= original) destination Packet data pointer for later usage * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    base_packet_data_ptr = dst_packet_data_ptr;

    /* * * * * * * * * * * * * * * * * * */
    /* * * * Header part building  * * * */
    /* * * * * * * * * * * * * * * * * * */

    ret_status = sn_coap_builder_header_build(&dst_packet_data_ptr, src_coap_msg_ptr);

    if (ret_status != 0)
    {
        /* Header building failed */
        return -1;
    }

    /* If else than Reset message because Reset message must be empty */
    if (src_coap_msg_ptr->msg_type != COAP_MSG_TYPE_RESET)
    {
        /* * * * * * * * * * * * * * * * * * */
        /* * * * Options part building * * * */
        /* * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build(&dst_packet_data_ptr, src_coap_msg_ptr);

        if (ret_status != 0)
        {
            /* Options building failed */
            return -1;
        }

        /* * * * * * * * * * * * * * * * * * */
        /* * * * Payload part building * * * */
        /* * * * * * * * * * * * * * * * * * */

        sn_coap_builder_payload_build(&dst_packet_data_ptr, src_coap_msg_ptr);
    }

    /* * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Return built Packet data length * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * */

    return (dst_packet_data_ptr - base_packet_data_ptr);
}

/**
 * \fn uint16_t sn_coap_builder_calc_needed_packet_data_size(sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Calculates needed Packet data memory size for given CoAP message
 *
 * \param *src_coap_msg_ptr is pointer to data which needed Packet
 *  		data length is calculated
 *
 * \return Return value is count of needed memory as bytes for build Packet data
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
uint16_t sn_coap_builder_calc_needed_packet_data_size(sn_coap_hdr_s *src_coap_msg_ptr)
{
    uint16_t returned_byte_count = 0;

    /* * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Count needed memory for Header * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * */

    /* Header size is fixed */
    returned_byte_count = COAP_HEADER_LENGTH;

    /* If else than Reset message because Reset message must be empty */
    if (src_coap_msg_ptr->msg_type != COAP_MSG_TYPE_RESET)
    {
        /* * * * * * * * * * * * * * * * * * * * * * * */
        /* * * * Count needed memory for Options * * * */
        /* * * * * * * * * * * * * * * * * * * * * * * */

        if (src_coap_msg_ptr->uri_path_ptr != NULL)
        {
            /* Get Path size with function which counts needed memory because Path is split to several Uri-Path Options*/
            /* E.g. Path temp1/temp2/temp3 is split to 3 Uri-Path Options */
        	/* Length of this option is 0-255 */
            returned_byte_count += sn_coap_builder_options_calc_option_size(src_coap_msg_ptr->uri_path_len,
                                                                          src_coap_msg_ptr->uri_path_ptr, COAP_OPTION_URI_PATH);
        }

        if (src_coap_msg_ptr->token_ptr != NULL)
        {
            /* Add needed memory for Option number and Option value length (length of this option is 1-8 bytes) */
            returned_byte_count++;

            if(src_coap_msg_ptr->token_len > 8)
            	src_coap_msg_ptr->token_len = 8;

            /* Add needed memory for Option value */
            returned_byte_count += src_coap_msg_ptr->token_len;
        }

        if (src_coap_msg_ptr->content_type_ptr != NULL)
        {
            /* Add needed memory for Option number and Option value length (length of this option is 0-2 bytes) */
            returned_byte_count++;

            if(src_coap_msg_ptr->content_type_len > 2)
            	src_coap_msg_ptr->content_type_len = 2;

            /* Add needed memory for Option value */
            returned_byte_count += src_coap_msg_ptr->content_type_len;
        }

        if (src_coap_msg_ptr->options_list_ptr != NULL)
        {
            if (src_coap_msg_ptr->options_list_ptr->max_age_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 0-4 bytes) */
                returned_byte_count++;

                if(src_coap_msg_ptr->options_list_ptr->max_age_len > 4)
                	src_coap_msg_ptr->options_list_ptr->max_age_len = 4;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->max_age_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->proxy_uri_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is  1-1034 bytes) */
                if (src_coap_msg_ptr->options_list_ptr->proxy_uri_len < 15)
                {
                    returned_byte_count++;
                }
                else if(src_coap_msg_ptr->options_list_ptr->proxy_uri_len >= 15 && src_coap_msg_ptr->options_list_ptr->proxy_uri_len <= 269)
                {
                    /* Option value length needs extra byte */
                    returned_byte_count += 2;
                }
				else if(src_coap_msg_ptr->options_list_ptr->proxy_uri_len >= 270 && src_coap_msg_ptr->options_list_ptr->proxy_uri_len <= 524)
				{
					/* Option value length needs extra bytes */
					returned_byte_count += 3;
				}
				else if(src_coap_msg_ptr->options_list_ptr->proxy_uri_len >= 525 && src_coap_msg_ptr->options_list_ptr->proxy_uri_len <= 779)
				{
					/* Option value length needs extra bytes */
					returned_byte_count += 4;
				}
				else if(src_coap_msg_ptr->options_list_ptr->proxy_uri_len >= 780 && src_coap_msg_ptr->options_list_ptr->proxy_uri_len <= 1034)
				{
					/* Option value length needs extra bytes */
					returned_byte_count += 5;
				}
				else
				{
					src_coap_msg_ptr->options_list_ptr->proxy_uri_len = 1034;
					returned_byte_count += 5;
				}

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->proxy_uri_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->etag_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 1-8 bytes) */
                returned_byte_count++;

                /* Add needed memory for Option value */
                if(src_coap_msg_ptr->options_list_ptr->etag_len > 8)
                	src_coap_msg_ptr->options_list_ptr->etag_len = 8;

                returned_byte_count += src_coap_msg_ptr->options_list_ptr->etag_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->uri_host_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 1-255 bytes) */
                if (src_coap_msg_ptr->options_list_ptr->uri_host_len < 15)
                {
                    returned_byte_count++;
                }
 				else if(src_coap_msg_ptr->options_list_ptr->uri_host_len >= 15 && src_coap_msg_ptr->options_list_ptr->uri_host_len <= 255)
                {
                    /* Option value length needs extra byte */
                    returned_byte_count += 2;
                }
 				else
 				{
 					src_coap_msg_ptr->options_list_ptr->uri_host_len = 255;
 					returned_byte_count += 2;
 				}

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->uri_host_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->location_path_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 0-255 bytes) */
                if (src_coap_msg_ptr->options_list_ptr->location_path_len < 15)
                {
                    returned_byte_count++;
                }
                else if (src_coap_msg_ptr->options_list_ptr->location_path_len >= 15 && src_coap_msg_ptr->options_list_ptr->location_path_len <= 255)
                {
                    /* Option value length needs extra byte */
                    returned_byte_count += 2;
                }

                else
                {
                	src_coap_msg_ptr->options_list_ptr->location_path_len = 255;

                    /* Option value length needs extra byte */
                    returned_byte_count += 2;

                }

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->location_path_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->uri_port_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 0-2 bytes) */
                returned_byte_count++;

                if(src_coap_msg_ptr->options_list_ptr->uri_port_len > 2)
                	src_coap_msg_ptr->options_list_ptr->uri_port_len = 2;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->uri_port_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->location_query_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 0-255 bytes) */
                if (src_coap_msg_ptr->options_list_ptr->location_query_len < 15)
                {
                    returned_byte_count++;
                }
                else if (src_coap_msg_ptr->options_list_ptr->location_query_len >= 15 && src_coap_msg_ptr->options_list_ptr->location_query_len <= 255)
                {
                    /* Option value length needs extra byte */
                    returned_byte_count += 2;
                }
                else if (src_coap_msg_ptr->options_list_ptr->location_query_len > 255)
                	src_coap_msg_ptr->options_list_ptr->location_query_len = 255;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->location_query_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->observe_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 0-2 bytes) */
                returned_byte_count++;

                if(src_coap_msg_ptr->options_list_ptr->observe_len > 2)
                	src_coap_msg_ptr->options_list_ptr->observe_len = 2;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->observe_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->uri_query_ptr != NULL)
            {
            	// 1-255
                returned_byte_count += sn_coap_builder_options_calc_option_size(src_coap_msg_ptr->options_list_ptr->uri_query_len,
                                                                              src_coap_msg_ptr->options_list_ptr->uri_query_ptr, COAP_OPTION_URI_QUERY);

            }

            if (src_coap_msg_ptr->options_list_ptr->block2_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 1-3 bytes) */
                returned_byte_count++;

                if(src_coap_msg_ptr->options_list_ptr->block2_len > 3)
                	src_coap_msg_ptr->options_list_ptr->block2_len = 3;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->block2_len;
            }

            if (src_coap_msg_ptr->options_list_ptr->block1_ptr != NULL)
            {
                /* Add needed memory for Option number and Option value length (length of this option is 1-3 bytes) */
                returned_byte_count++;

                if(src_coap_msg_ptr->options_list_ptr->block1_len > 2)
                	src_coap_msg_ptr->options_list_ptr->block1_len = 2;

                /* Add needed memory for Option value */
                returned_byte_count += src_coap_msg_ptr->options_list_ptr->block1_len;
            }
        }

        /* * * * * * * * * * * * * * * * * * * * * * * */
        /* * * * Count needed memory for Payload * * * */
        /* * * * * * * * * * * * * * * * * * * * * * * */

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
        if (src_coap_msg_ptr->payload_len > SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE)
        {
        	/* Two bytes for Block option */
            returned_byte_count += 2;

            if (src_coap_msg_ptr->msg_code < COAP_MSG_CODE_RESPONSE_CREATED )
            {
                returned_byte_count += sn_coap_builder_options_calculate_jump_need(src_coap_msg_ptr, 1);
            }
            else /* Response message */
            {
                returned_byte_count += sn_coap_builder_options_calculate_jump_need(src_coap_msg_ptr, 2);
            }
			/* Add maximum payload at one Blockwise message */
			returned_byte_count += SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE;
        }
        else
        {
        	if(src_coap_msg_ptr->msg_code <= COAP_MSG_CODE_REQUEST_DELETE)
        	{
                returned_byte_count += sn_coap_builder_options_calculate_jump_need(src_coap_msg_ptr, 1);
        	}
        	else
        	{
                returned_byte_count += sn_coap_builder_options_calculate_jump_need(src_coap_msg_ptr, 0);
        	}
        		/* Add wanted payload */
        	returned_byte_count += src_coap_msg_ptr->payload_len;
        }

#else /* !SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE */
        /* Add wanted payload */
        returned_byte_count += src_coap_msg_ptr->payload_len;
        returned_byte_count += sn_coap_builder_options_calculate_jump_need(src_coap_msg_ptr, 0);
#endif /* SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE */
    }

    return returned_byte_count;
}

/**
 * \fn void sn_coap_builder_release_allocated_send_msg_mem(sn_nsdl_transmit_s *freed_send_msg_ptr)
 *
 * \brief Releases memory of given Sending message
 *
 * \param *freed_send_msg_ptr is pointer to released Sending message
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
void sn_coap_builder_release_allocated_send_msg_mem(sn_nsdl_transmit_s *freed_send_msg_ptr)
{
    if (freed_send_msg_ptr != NULL)
    {
        if (freed_send_msg_ptr->dst_addr_ptr != NULL)
        {
            if (freed_send_msg_ptr->dst_addr_ptr->addr_ptr != NULL)
            {
                sn_coap_free(freed_send_msg_ptr->dst_addr_ptr->addr_ptr);
            }

            sn_coap_free(freed_send_msg_ptr->dst_addr_ptr);
        }

        if (freed_send_msg_ptr->packet_ptr != NULL)
        {
            sn_coap_free(freed_send_msg_ptr->packet_ptr);
        }

        sn_coap_free(freed_send_msg_ptr);
    }
}

/**
 * \fn uint8_t sn_coap_builder_options_calculate_jump_need(sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Checks if there is need for option jump
 *
 * \param  *src_coap_msg_ptr is source of checked CoAP message
 *
 * \param  block option marks if block option is to be added to message later. 0 = no block option, 1 = block1 and 2 = block2
 *
 * \return Returns bytes needed for jumping
 */

uint8_t sn_coap_builder_options_calculate_jump_need(sn_coap_hdr_s *src_coap_msg_ptr, uint8_t block_option)
{
    uint8_t previous_option_number = 0;
    uint8_t needed_space 		   = 0;


    if (src_coap_msg_ptr->options_list_ptr != NULL)
    {
        /* If option numbers greater than 14 is not used, then jumping is not needed */
        if(!src_coap_msg_ptr->options_list_ptr->uri_query_ptr 		&&
        	!src_coap_msg_ptr->options_list_ptr->accept_ptr 		&&
        	!src_coap_msg_ptr->token_ptr 							&&
        	!src_coap_msg_ptr->options_list_ptr->location_query_ptr &&
        	!src_coap_msg_ptr->options_list_ptr->block2_ptr 		&&
        	!src_coap_msg_ptr->options_list_ptr->block1_ptr			&&
        	!src_coap_msg_ptr->options_list_ptr->proxy_uri_ptr		&&
        	!block_option)
        		return 0;

    	if (src_coap_msg_ptr->options_list_ptr->uri_host_ptr != NULL)
        {
    		previous_option_number = (COAP_OPTION_URI_HOST);
        }

        if (src_coap_msg_ptr->options_list_ptr->etag_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_ETAG);
        }

        if (src_coap_msg_ptr->options_list_ptr->observe_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_OBSERVE);
        }

        if (src_coap_msg_ptr->options_list_ptr->uri_port_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_URI_PORT);
        }

        if (src_coap_msg_ptr->options_list_ptr->location_path_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_LOCATION_PATH);
        }

        if (src_coap_msg_ptr->uri_path_ptr!= NULL)
        {
        	previous_option_number = (COAP_OPTION_URI_PATH);
        }
        if (src_coap_msg_ptr->content_type_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_CONTENT_FORMAT);
        }
        if (src_coap_msg_ptr->options_list_ptr->max_age_ptr != NULL)
        {
        	previous_option_number = (COAP_OPTION_MAX_AGE);
        }

        if (src_coap_msg_ptr->options_list_ptr->uri_query_ptr != NULL)
        {
        	if((COAP_OPTION_URI_QUERY - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_URI_QUERY);
        }
        if (src_coap_msg_ptr->options_list_ptr->accept_ptr != NULL)
        {
        	if((COAP_OPTION_ACCEPT - previous_option_number) > 14)
        		needed_space += 1;
			previous_option_number = (COAP_OPTION_ACCEPT);
        }
        if (src_coap_msg_ptr->token_ptr != NULL)
        {
        	if((COAP_OPTION_TOKEN - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (	COAP_OPTION_TOKEN);
        }
        if (src_coap_msg_ptr->options_list_ptr->location_query_ptr != NULL)
        {
        	if((COAP_OPTION_LOCATION_QUERY - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_LOCATION_QUERY);
        }
        if (src_coap_msg_ptr->options_list_ptr->block2_ptr != NULL)
        {
        	if((COAP_OPTION_BLOCK2 - previous_option_number) > 14 || (block_option == 2 && (COAP_OPTION_BLOCK2 - previous_option_number) > 14 ))
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_BLOCK2);
        }
        if (src_coap_msg_ptr->options_list_ptr->block1_ptr != NULL)
        {
        	if((COAP_OPTION_BLOCK1 - previous_option_number) > 14 || (block_option == 1 && (COAP_OPTION_BLOCK1 - previous_option_number) > 14 ))
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_BLOCK1);
        }
        if (src_coap_msg_ptr->options_list_ptr->proxy_uri_ptr != NULL)
        {
        	if((COAP_OPTION_PROXY_URI - previous_option_number) > 14)
        		needed_space += 1;
        	if((COAP_OPTION_PROXY_URI - previous_option_number) > 29)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_PROXY_URI);
        }
    }

    else
    {
    	if(src_coap_msg_ptr->uri_path_ptr != 0)
    	{
        	if((COAP_OPTION_URI_PATH - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_URI_PATH);
    	}

    	if(src_coap_msg_ptr->content_type_ptr != 0)
    	{
        	if((COAP_OPTION_CONTENT_FORMAT - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_CONTENT_FORMAT);
    	}

    	if(src_coap_msg_ptr->token_ptr != 0)
		{
        	if((COAP_OPTION_TOKEN - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_TOKEN);
		}


    	if(block_option == 2)
    	{
        	if((COAP_OPTION_BLOCK2 - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_BLOCK2);
    	}
    	if(block_option == 1)
    	{
        	if((COAP_OPTION_BLOCK1 - previous_option_number) > 14)
        		needed_space += 1;
        	previous_option_number = (COAP_OPTION_BLOCK1);
    	}
    }
    return needed_space;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int8_t sn_coap_builder_header_build(uint8_t **dst_packet_data_pptr,
                                           sn_coap_hdr_s *src_coap_msg_ptr)
{
    /* * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Check validity of Header values * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * */

    int8_t ret_status = sn_coap_header_validity_check(src_coap_msg_ptr, COAP_VERSION);

    if (ret_status != 0)
    {
        /* Header values validity check failed */
        return -1;
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Build Header part of Packet data  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * */

    /* * * Add CoAP Version * * */
    COAP_HEADER_VERSION_DATA += COAP_VERSION;

    /* * * Add Message type * * */
    COAP_HEADER_MSG_TYPE_DATA += src_coap_msg_ptr->msg_type;

    /* * * Add Message code * * */
    COAP_HEADER_MSG_CODE_DATA = src_coap_msg_ptr->msg_code;

    /* * * Add Message ID * * */
    COAP_HEADER_MSG_ID_DATA_MSB = (uint8_t)(src_coap_msg_ptr->msg_id >> COAP_HEADER_MSG_ID_MSB_SHIFT); /* MSB part */
    COAP_HEADER_MSG_ID_DATA_LSB = (uint8_t)src_coap_msg_ptr->msg_id;                                   /* LSB part */

    /* * * * * * * * * * * * * * * * * * * */
    /* * * * Examine length of Header  * * */
    /* * * * * * * * * * * * * * * * * * * */

    /* Increase destination Packet data pointer */
    (*dst_packet_data_pptr) += COAP_HEADER_LENGTH;

    /* Success */
    return 0;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int8_t sn_coap_builder_options_build(uint8_t **dst_packet_data_pptr,
                                            sn_coap_hdr_s *src_coap_msg_ptr)
{
    uint16_t ret_status = 0;

    /* * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Check if Options are used at all  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * */

    if (src_coap_msg_ptr->uri_path_ptr == NULL &&
        src_coap_msg_ptr->token_ptr == NULL &&
        src_coap_msg_ptr->content_type_ptr == NULL &&
        src_coap_msg_ptr->options_list_ptr == NULL)
    {
        return 0;
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Initialize previous Option number for new built message * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    global_previous_option_number = 0;

    /* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
    /* Note: Options must be in Option number order in Packet data, */
    /* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

    //missing: COAP_OPTION_IF_MATCH, COAP_OPTION_IF_NONE_MATCH, COAP_OPTION_SIZE

    /* Check if less used options are used at all */
    if (src_coap_msg_ptr->options_list_ptr != NULL)
    {

    	/* * * * * * * * * * * * * * * * * * */
        /* * * * Build Uri-Host option * * * */
        /* * * * * * * * * * * * * * * * * * */
   		ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->uri_host_len,
                                                                  src_coap_msg_ptr->options_list_ptr->uri_host_ptr,
                                                                  COAP_OPTION_URI_HOST);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

        /* * * * * * * * * * * * * * * * * */
        /* * * * Build ETag option  * * * */
        /* * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->etag_len,
                                                                  src_coap_msg_ptr->options_list_ptr->etag_ptr,
                                                                  COAP_OPTION_ETAG);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

        /* * * * * * * * * * * * * * * * * * * * */
        /* * * * Build Observe option  * * * * */
        /* * * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->observe_len,
                                                                  src_coap_msg_ptr->options_list_ptr->observe_ptr,
                                                                  COAP_OPTION_OBSERVE);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

		/* * * * * * * * * * * * * * * * * * */
		/* * * * Build Uri-Port option * * * */
		/* * * * * * * * * * * * * * * * * * */

		ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
																 src_coap_msg_ptr->options_list_ptr->uri_port_len,
																 src_coap_msg_ptr->options_list_ptr->uri_port_ptr,
																 COAP_OPTION_URI_PORT);

		if (ret_status == -1)
		{
			/* Option value building failed */
			return -1;
		}


        /* * * * * * * * * * * * * * * * * * * * * */
        /* * * * Build Location-Path option  * * * */
        /* * * * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_multiple_option(dst_packet_data_pptr,
        																&src_coap_msg_ptr->options_list_ptr->location_path_ptr,
        																&src_coap_msg_ptr->options_list_ptr->location_path_len,
        																COAP_OPTION_LOCATION_PATH);

         if (ret_status == -1)
         {
             /* Option value building failed */
             return -1;
         }

    }


    /* * * * * * * * * * * * * * * * * * */
    /* * * * Build Uri-Path option * * * */
    /* * * * * * * * * * * * * * * * * * */

    /* Here are added Path parts automatically, so other function used than with other functions */
    /* E.g: This function makes three Uri-Path options from following path: temp1/temp2/temp3 */
    ret_status = sn_coap_builder_options_build_add_multiple_option(dst_packet_data_pptr,
    																&src_coap_msg_ptr->uri_path_ptr,
    																&src_coap_msg_ptr->uri_path_len,
    																COAP_OPTION_URI_PATH);

    if (ret_status == -1)
    {
        /* Option value building failed */
        return -1;
    }


    /* * * * * * * * * * * * * * * * * * * * */
    /* * * * Build Content-Type option * * * */
    /* * * * * * * * * * * * * * * * * * * * */

    ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->content_type_len,
                                                                  src_coap_msg_ptr->content_type_ptr,
                                                                  COAP_OPTION_CONTENT_FORMAT);

    if (ret_status == -1)
    {
    	/* Option value building failed */
    	return -1;
    }

    /* Check if less used options are used at all */
    if (src_coap_msg_ptr->options_list_ptr != NULL)
    {
    	/* * * * * * * * * * * * * * * * * * */
        /* * * * Build Max-Age option  * * * */
        /* * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->max_age_len,
                                                                  src_coap_msg_ptr->options_list_ptr->max_age_ptr,
                                                                  COAP_OPTION_MAX_AGE);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

        /* * * * * * * * * * * * * * * * * * * * */
        /* * * * Build Uri-Query option  * * * * */
        /* * * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_multiple_option(dst_packet_data_pptr,
        															&src_coap_msg_ptr->options_list_ptr->uri_query_ptr,
        															&src_coap_msg_ptr->options_list_ptr->uri_query_len,
        															COAP_OPTION_URI_QUERY);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

        ret_status = sn_coap_builder_options_build_add_multiple_option(dst_packet_data_pptr,
        															&src_coap_msg_ptr->options_list_ptr->accept_ptr,
        															&src_coap_msg_ptr->options_list_ptr->accept_len,
        															COAP_OPTION_ACCEPT);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

    }


    /* * * * * * * * * * * * * * * * * */
    /* * * * Build Token option  * * * */
    /* * * * * * * * * * * * * * * * * */

    ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                              src_coap_msg_ptr->token_len,
                                                              src_coap_msg_ptr->token_ptr,
                                                              COAP_OPTION_TOKEN);

    if (ret_status == -1)
    {
        /* Option value building failed */
        return -1;
    }

    /* Check if less used options are used at all */
    if (src_coap_msg_ptr->options_list_ptr != NULL)
    {

    	/* * * * * * * * * * * * * * * * * * * * * */
        /* * * * Build Location-Query option * * * */
        /* * * * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->location_query_len,
                                                                  src_coap_msg_ptr->options_list_ptr->location_query_ptr,
                                                                  COAP_OPTION_LOCATION_QUERY);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

		/* * * * * * * * * * * * * * * * * * */
		/* * * * Build Block2 option * * * * */
		/* * * * * * * * * * * * * * * * * * */

		ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
																  src_coap_msg_ptr->options_list_ptr->block2_len,
																  src_coap_msg_ptr->options_list_ptr->block2_ptr,
																  COAP_OPTION_BLOCK2);

		if (ret_status == -1)
		{
			/* Option value building failed */
			return -1;
		}

		/* * * * * * * * * * * * * * * * * * */
		/* * * * Build Block1 option * * * * */
		/* * * * * * * * * * * * * * * * * * */

		ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
																  src_coap_msg_ptr->options_list_ptr->block1_len,
																  src_coap_msg_ptr->options_list_ptr->block1_ptr,
																  COAP_OPTION_BLOCK1);

		if (ret_status == -1)
		{
			/* Option value building failed */
			return -1;
		}

		/* * * * * * * * * * * * * * * * * * * */
        /* * * * Build Proxy-Uri option * * * */
        /* * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                  src_coap_msg_ptr->options_list_ptr->proxy_uri_len,
                                                                  src_coap_msg_ptr->options_list_ptr->proxy_uri_ptr,
                                                                  COAP_OPTION_PROXY_URI);

        if (ret_status == -1)
        {
            /* Option value building failed */
            return -1;
        }

    }

    /* Great success */
    return 0;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int16_t sn_coap_builder_options_build_add_one_option(uint8_t **dst_packet_data_pptr,
                                                            uint16_t option_value_len,
                                                            uint8_t *option_value_ptr,
                                                            sn_coap_option_numbers_e option_number)
{
    /* Check if there is option at all */
    if (option_value_ptr != NULL)
    {
        int16_t ret_status = 0;
        uint8_t option_value;

        /* * * Add Option number * * */
        option_value = (option_number - global_previous_option_number);
        if(option_value > 14 && option_value < 30)
        {
        	 **dst_packet_data_pptr = 0xf1;
        	 *dst_packet_data_pptr += 1;

        	 option_value -= 15;
        }
        else if(option_value >= 30 && option_value < 258)
        {
       	 **dst_packet_data_pptr = 0xf2;
       	 *dst_packet_data_pptr += 1;

       	**dst_packet_data_pptr = (option_number / 16);
       	 option_value -= ((**dst_packet_data_pptr + 2) * 8);
         *dst_packet_data_pptr += 1;

        }

        **dst_packet_data_pptr = (option_value << COAP_OPTIONS_OPTION_NUMBER_SHIFT);
        global_previous_option_number = option_number;

        /* * * Add Option value length * * */

        ret_status = sn_coap_builder_options_add_option_value_len(option_value_len, dst_packet_data_pptr);

        if (ret_status != 0)
        {
            return -1;
        }

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr) += ret_status;

        /* * * Add Option value * * */

        /* Write Option value */
        memcpy(*dst_packet_data_pptr, option_value_ptr, option_value_len);

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr) += option_value_len;

        /* * * * * * * * * * * * * * * * * * * * * * * * * * * */
        /* * * * Increase Options count info in Header * * * * */
        /* * * * * * * * * * * * * * * * * * * * * * * * * * * */

        ret_status = sn_coap_builder_options_increase_count_in_header(1);

        if (ret_status != 0)
        {
            return -1;
        }
        return 1;
    }

    /* Great success */
    return 0;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int16_t sn_coap_builder_options_build_add_multiple_option(uint8_t **dst_packet_data_pptr,
                                                          uint8_t **src_pptr, uint16_t *src_len_ptr, sn_coap_option_numbers_e option)
{
    /* Check if there is Uri-Path option at all */
	if (*src_pptr != NULL)
    {
        uint8_t    *query_ptr            	= *src_pptr;
        uint8_t     query_part_count     	= 0;
        uint16_t    query_len            	= *src_len_ptr;
        uint8_t     i                   	= 0;
        uint16_t    query_part_offset    	= 0;
        int16_t     ret_status          	= 0;

        /* Get query part count */
        query_part_count = sn_coap_builder_options_get_option_part_count(query_len, query_ptr, option);

        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
        /* * * * Build Uri-query options by adding all query parts to Uri-query options * * * */
        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
        for (i = 0; i < query_part_count; i++)
        {
            /* Get length of query part */
            uint16_t one_query_part_len = sn_coap_builder_options_get_option_part_length_from_whole_option_string(query_len,
                                                                                                      query_ptr,
                                                                                                      i, option);

            /* Get position of query part */
            query_part_offset = sn_coap_builder_options_get_option_part_position(query_len, query_ptr, i, option);

            /* Add Uri-query's one part to Options */
           ret_status = sn_coap_builder_options_build_add_one_option(dst_packet_data_pptr,
                                                                      one_query_part_len,
                                                                      *src_pptr + query_part_offset,
                                                                      option);

            if (ret_status == -1)
            {
                /* Option value building failed */
                return -1;
            }
        }
    }

    /* Success */
    return 0;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static uint16_t sn_coap_builder_options_calc_option_size(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
{
    uint8_t     query_part_count    = sn_coap_builder_options_get_option_part_count(query_len, query_ptr, option);
    uint8_t     i                   = 0;
    uint16_t    ret_value           = 0;

    /* * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Calculate Uri-query options length  * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * */
    for (i = 0; i < query_part_count; i++)
    {
        /* * * Length of Option number and Option value length * * */

        /* Get length of Query part */
    	uint16_t one_query_part_len = sn_coap_builder_options_get_option_part_length_from_whole_option_string(query_len,
        																							query_ptr,
                                                                                                  i, option);

        /* Check if 4 bits are enough for writing Option value length */
        if (one_query_part_len < 15)
        {
            /* 4 bits are enough for Option value length */
            ret_value++;
        }
        else if (one_query_part_len >= 15 && one_query_part_len < 270)
        {
            /* Extra byte for Option value length is needed */
            ret_value += 2;
        }
        else if (one_query_part_len >= 270 && one_query_part_len < 525)
        {
            /* Extra byte for Option value length is needed */
            ret_value += 3;
        }
        else if (one_query_part_len >= 525 && one_query_part_len < 780)
        {
            /* Extra byte for Option value length is needed */
            ret_value += 4;
        }
        else if (one_query_part_len >= 780 && one_query_part_len <= 1034)
        {
            /* Extra byte for Option value length is needed */
            ret_value += 5;
        }

        /* * * Length of Option value * * */

        /* Increase options length */
        ret_value += one_query_part_len;
    }

    /* Success */
    return ret_value;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static uint8_t sn_coap_builder_options_get_option_part_count(uint16_t query_len, uint8_t *query_ptr, sn_coap_option_numbers_e option)
{
    uint8_t  temp_char            = 0;
    uint8_t  returned_query_count = 0;
    uint16_t query_len_index      = 0;
    uint8_t  char_to_search		  = 0;

    if(option == COAP_OPTION_URI_QUERY)
    	char_to_search = '&';
    else if(option == COAP_OPTION_URI_PATH)
    	char_to_search = '/';

    /* Loop whole query and search '\0' characters */
    for (query_len_index = 0; query_len_index < query_len; query_len_index++)
    {
        /* Store character to temp_char for helping debugging */
        temp_char = *query_ptr;

        /* If new query part starts */
        if (temp_char == char_to_search && query_len_index > 0) /* query_len_index > 0 is for querys which start with "\0" */
        {
            returned_query_count++;
        }

        query_ptr++;
    }

    /* If not yet added last query part */
    if (temp_char != 0)
    {
        returned_query_count++;
    }

    return returned_query_count;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static uint16_t sn_coap_builder_options_get_option_part_length_from_whole_option_string(uint16_t query_len,
                                                                             uint8_t *query_ptr,
                                                                             uint8_t query_index, sn_coap_option_numbers_e option)
{
    uint16_t returned_query_part_len = 0;
    uint8_t  temp_query_index        = 0;
    uint16_t query_len_index         = 0;
    uint8_t  char_to_search		 	 = 0;

    if(option == COAP_OPTION_URI_QUERY)
    	char_to_search = '&';
    else if(option == COAP_OPTION_URI_PATH)
    	char_to_search = '/';

    /* Loop whole query and search '\0' characters */
    for (query_len_index = 0; query_len_index < query_len; query_len_index++)
    {
        /* Store character to temp_char for helping debugging */
        uint8_t temp_char = *query_ptr;

        /* If new query part starts */
        if (temp_char == char_to_search && returned_query_part_len > 0) /* returned_query_part_len > 0 is for querys which start with "\0" */
        {
            /* If query part index is wanted */
            if (temp_query_index == query_index)
            {
                /* Return length of query part */
                return returned_query_part_len;
            }
            else
            {
                /* Reset length of query part because wanted query part finding continues*/
                returned_query_part_len = 0;
            }

            /* Next query part is looped */
            temp_query_index++;
        }
        else if (temp_char != char_to_search) /* Else if query part continues */
        {
            /* Increase query part length */
            returned_query_part_len++;
        }

        query_ptr++;
    }

    /* Return length of query part in cases that query part does not finish to '\0' character (last query part can be like that) */
    return returned_query_part_len;
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
SN_MEM_ATTR_COAP_BUILDER_FUNC
static uint16_t sn_coap_builder_options_get_option_part_position(uint16_t query_len,
                                                               uint8_t *query_ptr,
                                                               uint8_t query_index, sn_coap_option_numbers_e option)
{
    uint16_t returned_query_part_offset = 0;
    uint8_t  temp_query_index           = 0;
    uint16_t query_len_index            = 0;
    uint8_t	 char_to_search				= 0;

    if (query_index == 0)
    {
        if (*query_ptr == 0)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }

    if(option == COAP_OPTION_URI_QUERY)
    	char_to_search = '&';
    else if(option == COAP_OPTION_URI_PATH)
    	char_to_search = '/';

    /* Loop whole query and search separator characters */
    for (query_len_index = 0; query_len_index < query_len; query_len_index++)
    {
        /* Store character to temp_char for helping debugging */
        uint8_t temp_char = *query_ptr;

        /* If new query part starts */
        if (temp_char == char_to_search && returned_query_part_offset > 0) /* returned_query_part_offset > 0 is for querys which start with searched char */
        {
            /* If query part index is wanted */
            if (temp_query_index == (query_index - 1))
            {
                /* Return offset of query part */
                return (returned_query_part_offset + 1); /* Plus one is for passing separator */
            }

            /* Next query part is looped */
            temp_query_index++;
        }

        returned_query_part_offset++;

        query_ptr++;
    }

    return -1;
}

/**
 * \fn SN_MEM_ATTR_COAP_BUILDER_FUNC static int8_t sn_coap_builder_options_increase_count_in_header(uint8_t increased_options_count)
 *
 * \brief Increases Option count in Header
 *
 * \param increased_options_count is count how much Options count is increased
 *
 * \return Return value is 0 in ok case and -1 in failure case
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int8_t sn_coap_builder_options_increase_count_in_header(uint8_t increased_options_count)
{
    int8_t new_options_count = 0;
    int8_t ret_status        = 0;

    /* Check that new Options count is not too big */

    new_options_count = (COAP_HEADER_OPTIONS_COUNT_DATA & COAP_HEADER_OPTIONS_COUNT_MASK) + increased_options_count;

    ret_status = sn_coap_header_validity_check_options_count(new_options_count);

    if (ret_status != 0)
    {
        return -1;
    }
    else
    {
        /* Add wanted Options count to Header */
        COAP_HEADER_OPTIONS_COUNT_DATA += increased_options_count;

        /* Success */
        return 0;
    }
}

/**
 * \fn SN_MEM_ATTR_COAP_BUILDER_FUNC static int16_t sn_coap_builder_options_add_option_value_len(uint16_t option_value_len, uint8_t **dst_packet_data_pptr)
 *
 * \brief Adds Option value length to Packet data
 *
 * \param option_value_len is Option value length to be added
 *
 * \param**dst_packet_data_pptr is destination for built Packet data
 *
 * \return Return value is count of needed memory as bytes for Path option
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
static int16_t sn_coap_builder_options_add_option_value_len(uint16_t option_value_len, uint8_t **dst_packet_data_pptr)
{
    /* * Check validity of Option length * */

    int8_t ret_status = sn_coap_builder_options_check_validity_option_len(option_value_len);

    if (ret_status != 0)
    {
        /* Return error code */
        return -1;
    }

    /* Check if 4 bits are enough for writing Option value length */
    if (option_value_len < 15)
    {
        /* 4 bits are enough for Option value length */

        /* Write Option value length */
        **dst_packet_data_pptr += option_value_len;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;
    }

    else if(option_value_len >= 15 && option_value_len <= 269)
    {
        /* Extra byte for Option value length is needed */

        /* Write Option value length */
        **dst_packet_data_pptr += 0x0F;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;

        /* Write extra byte of Option value length */
        **dst_packet_data_pptr = option_value_len - 15;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;
    }

    else if(option_value_len >= 270 && option_value_len <= 524)
    {
        /* Extra bytes for Option value length is needed */

        /* Write Option value length */
        **dst_packet_data_pptr += 0x0F;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;

        **dst_packet_data_pptr = 0xFF;
        (*dst_packet_data_pptr)++;

        /* Write extra byte of Option value length */
        **dst_packet_data_pptr = option_value_len - 270;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;
    }

    else if(option_value_len >= 525 && option_value_len <= 779)
    {
        /* Extra bytes for Option value length is needed */

        /* Write Option value length */
        **dst_packet_data_pptr += 0x0F;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;

        **dst_packet_data_pptr = 0xFF;
        (*dst_packet_data_pptr)++;
        **dst_packet_data_pptr = 0xFF;
        (*dst_packet_data_pptr)++;


        /* Write extra byte of Option value length */
        **dst_packet_data_pptr = option_value_len - 525;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;
    }

    else if(option_value_len >= 780 && option_value_len <= 1034)
    {
        /* Extra bytes for Option value length is needed */

        /* Write Option value length */
        **dst_packet_data_pptr += 0x0F;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;

        **dst_packet_data_pptr = 0xFF;
		(*dst_packet_data_pptr)++;
		**dst_packet_data_pptr = 0xFF;
		(*dst_packet_data_pptr)++;
		**dst_packet_data_pptr = 0xFF;
		(*dst_packet_data_pptr)++;


        /* Write extra byte of Option value length */
        **dst_packet_data_pptr = option_value_len - 780;

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr)++;
    }

    /* Success */
    return 0;
}

/**
 * \fn SN_MEM_ATTR_COAP_BUILDER_FUNC static void sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
 *
 * \brief Builds Options part of Packet data
 *
 * \param **dst_packet_data_pptr is destination for built Packet data
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 */
SN_MEM_ATTR_COAP_BUILDER_FUNC
static void sn_coap_builder_payload_build(uint8_t **dst_packet_data_pptr, sn_coap_hdr_s *src_coap_msg_ptr)
{
    /* Check if Payload is used at all */
    if (src_coap_msg_ptr->payload_ptr != NULL)
    {
        /* Write Payload */
        memcpy(*dst_packet_data_pptr, src_coap_msg_ptr->payload_ptr, src_coap_msg_ptr->payload_len);

        /* Increase destination Packet data pointer */
        (*dst_packet_data_pptr) += src_coap_msg_ptr->payload_len;
    }
}
