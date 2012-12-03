/**
 *\file sn_coap_parser_ietf_draft_12.c
 *
 * \brief CoAP Header parser
 *
 * Functionality: Parses CoAP Header
 *
 *  Created on: Jun 30, 2011
 *      Author: tero
 *
 * \note Supports draft-ietf-core-coap-12
 */

/* * * * * * * * * * * * * * */
/* * * * INCLUDE FILES * * * */
/* * * * * * * * * * * * * * */

#include <stdio.h>
#include <stddef.h>
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

static void     sn_coap_parser_header_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, coap_version_e *coap_version_ptr);
static uint8_t  sn_coap_parser_options_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr);
static int8_t   sn_coap_parser_options_parse_multiple_options(uint8_t **packet_data_pptr, uint8_t options_count_left, uint8_t *previous_option_number_ptr, uint8_t **dst_ptr, uint16_t *dst_len_ptr, sn_coap_option_numbers_e option, uint16_t option_number_len);
static uint16_t sn_coap_parser_options_count_needed_memory_multiple_option(uint8_t *packet_data_ptr, uint8_t options_count_left, uint8_t previous_option_number, sn_coap_option_numbers_e option, uint16_t option_number_len);
static void     sn_coap_parser_payload_parse(uint16_t packet_data_len, uint8_t *packet_data_ptr, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr);

/* * * * * * * * * * * * * * * * * */
/* * * * GLOBAL DECLARATIONS * * * */
/* * * * * * * * * * * * * * * * * */

SN_MEM_ATTR_COAP_PARSER_DECL static uint8_t *base_packet_data_ptr; /* Base (= original) source Packet data pointer value */

/**
 * \fn sn_coap_hdr_s *sn_coap_parser(uint16_t packet_data_len, uint8_t *packet_data_ptr, coap_version_e *coap_version_ptr)
 *
 * \brief Parses CoAP message from given Packet data
 *
 * \param packet_data_len is length of given Packet data to be parsed to CoAP message
 *
 * \param *packet_data_ptr is source for Packet data to be parsed to CoAP message
 *
 * \param *coap_version_ptr is destination for parsed CoAP specification version
 *
 * \return Return value is pointer to parsed CoAP message.\n
 *         In following failure cases NULL is returned:\n
 *          -Failure in given pointer (= NULL)\n
 *          -Failure in memory allocation (malloc() returns NULL)
 */
SN_MEM_ATTR_COAP_PARSER_FUNC
sn_coap_hdr_s *sn_coap_parser(uint16_t packet_data_len,
                              uint8_t *packet_data_ptr,
                              coap_version_e *coap_version_ptr)
{
    uint8_t       *data_temp_ptr                    = packet_data_ptr;
    sn_coap_hdr_s *parsed_and_returned_coap_msg_ptr = NULL;
    uint8_t        ret_status                       = 0;

    /* * * * * * * * * * * * * * * * * */
    /* * * * Check given pointer * * * */
    /* * * * * * * * * * * * * * * * * */

    if (packet_data_ptr == NULL)
    {
        return NULL;
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Store base (= original) source Packet data pointer for later usage  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    base_packet_data_ptr = packet_data_ptr;

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Allocate memory for parsed and returned CoAP message  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    parsed_and_returned_coap_msg_ptr = sn_coap_malloc(sizeof(sn_coap_hdr_s));

    if (parsed_and_returned_coap_msg_ptr == NULL)
    {
        return NULL;
    }

    /* Initialize allocated memory with with zero values */
    memset(parsed_and_returned_coap_msg_ptr, 0x00, sizeof(sn_coap_hdr_s));

    /* * * * * * * * * * * * * * * */
    /* * * * Header parsing  * * * */
    /* * * * * * * * * * * * * * * */

    sn_coap_parser_header_parse(&data_temp_ptr, parsed_and_returned_coap_msg_ptr, coap_version_ptr);

    /* * * * * * * * * * * * * * * */
    /* * * * Options parsing * * * */
    /* * * * * * * * * * * * * * * */

    ret_status = sn_coap_parser_options_parse(&data_temp_ptr, parsed_and_returned_coap_msg_ptr);

    if (ret_status != 0)
    {
        /* Release memory of CoAP message */
        sn_coap_parser_release_allocated_coap_msg_mem(parsed_and_returned_coap_msg_ptr);

        return NULL;
    }

    /* * * * * * * * * * * * * * * */
    /* * * * Payload parsing * * * */
    /* * * * * * * * * * * * * * * */

    sn_coap_parser_payload_parse(packet_data_len, packet_data_ptr, &data_temp_ptr, parsed_and_returned_coap_msg_ptr);

    /* * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Return parsed CoAP message  * * * * */
    /* * * * * * * * * * * * * * * * * * * * * * */

    return parsed_and_returned_coap_msg_ptr;
}

/**
 * \fn void sn_coap_parser_release_allocated_coap_msg_mem(sn_coap_hdr_s *freed_coap_msg_ptr)
 *
 * \brief Releases memory of given CoAP message
 *
 *        Note!!! Does not release Payload part
 *
 * \param *freed_coap_msg_ptr is pointer to released CoAP message
 */
SN_MEM_ATTR_COAP_PARSER_FUNC
void sn_coap_parser_release_allocated_coap_msg_mem(sn_coap_hdr_s *freed_coap_msg_ptr)
{
    if (freed_coap_msg_ptr != NULL)
    {
        if (freed_coap_msg_ptr->uri_path_ptr != NULL)
        {
            sn_coap_free(freed_coap_msg_ptr->uri_path_ptr);
        }

        if (freed_coap_msg_ptr->token_ptr != NULL)
        {
            sn_coap_free(freed_coap_msg_ptr->token_ptr);
        }

        if (freed_coap_msg_ptr->content_type_ptr != NULL)
        {
            sn_coap_free(freed_coap_msg_ptr->content_type_ptr);
        }

        if (freed_coap_msg_ptr->options_list_ptr != NULL)
        {
            if (freed_coap_msg_ptr->options_list_ptr->max_age_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->max_age_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->proxy_uri_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->proxy_uri_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->etag_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->etag_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->uri_host_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->uri_host_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->location_path_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->location_path_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->uri_port_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->uri_port_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->location_query_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->location_query_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->observe_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->observe_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->uri_query_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->uri_query_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->block2_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->block2_ptr);
            }

            if (freed_coap_msg_ptr->options_list_ptr->block1_ptr != NULL)
            {
                sn_coap_free(freed_coap_msg_ptr->options_list_ptr->block1_ptr);
            }
            if (freed_coap_msg_ptr->options_list_ptr->accept_ptr != NULL)
             {
                 sn_coap_free(freed_coap_msg_ptr->options_list_ptr->accept_ptr);
             }

            sn_coap_free(freed_coap_msg_ptr->options_list_ptr);
        }

        sn_coap_free(freed_coap_msg_ptr);
    }
}

/**
 * \fn static void sn_coap_parser_header_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, coap_version_e *coap_version_ptr)
 *
 * \brief Parses CoAP message's Header part from given Packet data
 *
 * \param **packet_data_ptr is source for Packet data to be parsed to CoAP message
 *
 * \param *dst_coap_msg_ptr is destination for parsed CoAP message
 *
 * \param *coap_version_ptr is destination for parsed CoAP specification version
 */
SN_MEM_ATTR_COAP_PARSER_FUNC
static void sn_coap_parser_header_parse(uint8_t **packet_data_pptr,
                                        sn_coap_hdr_s *dst_coap_msg_ptr,
                                        coap_version_e *coap_version_ptr)
{
    /* * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Parse Header part of CoAP message * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * */

    /* Parse CoAP Version */
    *coap_version_ptr = (coap_version_e)(COAP_HEADER_VERSION_DATA & COAP_HEADER_VERSION_MASK);

    /* Parse Message type */
    dst_coap_msg_ptr->msg_type = (sn_coap_msg_type_e)(COAP_HEADER_MSG_TYPE_DATA & COAP_HEADER_MSG_TYPE_MASK);

    /* Parse Message code */
    dst_coap_msg_ptr->msg_code = (sn_coap_msg_code_e)COAP_HEADER_MSG_CODE_DATA;

    /* Parse Message ID */
    dst_coap_msg_ptr->msg_id = COAP_HEADER_MSG_ID_DATA_LSB;
    dst_coap_msg_ptr->msg_id += (COAP_HEADER_MSG_ID_DATA_MSB << COAP_HEADER_MSG_ID_MSB_SHIFT);

    /* * * * * * * * * * * * * * * * * * * */
    /* * * * Examine length of Header  * * */
    /* * * * * * * * * * * * * * * * * * * */

    (*packet_data_pptr) += COAP_HEADER_LENGTH;
}

/**
 * \fn static uint8_t sn_coap_parser_options_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr)
 *
 * \brief Parses CoAP message's Options part from given Packet data
 *
 * \param **packet_data_pptr is source of Packet data to be parsed to CoAP message
 * \param *dst_coap_msg_ptr is destination for parsed CoAP message
 *
 * \return Return value is 0 in ok case and -1 in failure case
 */
SN_MEM_ATTR_COAP_PARSER_FUNC
static uint8_t sn_coap_parser_options_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr)
{
    uint8_t options_count          = 0;
    uint8_t previous_option_number = 0;
    uint8_t i                      = 0;
    int8_t  ret_status             = 0;

    /* Get Options count from CoAP header */
    options_count = (COAP_HEADER_OPTIONS_COUNT_DATA & COAP_HEADER_OPTIONS_COUNT_MASK);

    /* Loop all Options */
    for (i = 0; i < options_count; i++)
    {
        uint8_t  option_number = (**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT);
        if(option_number == 15)
        {
        	option_number = sn_coap_parser_option_jump_parse(packet_data_pptr);
        	option_number += (**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT);
        }

        option_number += previous_option_number;

        uint16_t option_number_len = (**packet_data_pptr & 0x0F);
        if(option_number_len == 15)
        {
        	option_number_len = sn_coap_parser_option_number_len_parse(packet_data_pptr);
        }

        /* Some options are handled independently in own functions */
        if (option_number != COAP_OPTION_URI_PATH && option_number != COAP_OPTION_URI_QUERY && option_number != COAP_OPTION_LOCATION_PATH && option_number != COAP_OPTION_LOCATION_QUERY)
        {
            previous_option_number = option_number;

            (*packet_data_pptr)++;
        }

        switch (option_number)
        {
            case COAP_OPTION_MAX_AGE:
            case COAP_OPTION_PROXY_URI:
            case COAP_OPTION_ETAG:
            case COAP_OPTION_URI_HOST:
            case COAP_OPTION_LOCATION_PATH:
            case COAP_OPTION_URI_PORT:
            case COAP_OPTION_LOCATION_QUERY:
            case COAP_OPTION_OBSERVE:
            case COAP_OPTION_URI_QUERY:
            case COAP_OPTION_BLOCK2:
            case COAP_OPTION_BLOCK1:
                if (dst_coap_msg_ptr->options_list_ptr == NULL)
                {
                    dst_coap_msg_ptr->options_list_ptr = sn_coap_malloc(sizeof(sn_coap_options_list_s));
                    if(NULL == dst_coap_msg_ptr->options_list_ptr)
                    {
                    	return -1;
                    }
                	memset(dst_coap_msg_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
                }
                break;
        }

        switch (option_number)
        {
            case COAP_OPTION_CONTENT_FORMAT:
            	if((option_number_len > 2) || (dst_coap_msg_ptr->content_type_ptr))
            		return -1;
                dst_coap_msg_ptr->content_type_len = option_number_len;

                dst_coap_msg_ptr->content_type_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->content_type_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->content_type_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_MAX_AGE:
            	if((option_number_len > 4) || dst_coap_msg_ptr->options_list_ptr->max_age_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->max_age_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->max_age_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->max_age_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->max_age_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_PROXY_URI:
            	if ((option_number_len > 1034) || dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->proxy_uri_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_ETAG:
            	if((option_number_len > 8) || dst_coap_msg_ptr->options_list_ptr->etag_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->etag_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->etag_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->etag_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->etag_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_URI_HOST:
            	if((option_number_len > 255) || dst_coap_msg_ptr->options_list_ptr->uri_host_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->uri_host_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->uri_host_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->uri_host_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->uri_host_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_LOCATION_PATH:
            	if(dst_coap_msg_ptr->options_list_ptr->location_path_ptr)
            		return -1;
                /* This is managed independently because User gives this option in one character table */
            	ret_status = sn_coap_parser_options_parse_multiple_options(packet_data_pptr,
            	                                                                   options_count - i,
            	                                                                   &previous_option_number,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->location_path_ptr,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->location_path_len,
            	                                                                   COAP_OPTION_LOCATION_PATH,
            	                                                                   option_number_len);
                if (ret_status >= 0)
                {
                    i += (ret_status - 1); /* i += is because possible several Options are handled by sn_coap_parser_options_parse_uri_path() */
                }
                else
                {
                    return -1;
                }

                break;


            case COAP_OPTION_URI_PORT:
            	if((option_number_len > 2) || dst_coap_msg_ptr->options_list_ptr->uri_port_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->uri_port_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->uri_port_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->uri_port_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->uri_port_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_LOCATION_QUERY:
            	if(dst_coap_msg_ptr->options_list_ptr->location_query_ptr)
            		return -1;
                /* Uri-Path is managed independently because User gives Uri-Path in one character table */
            	ret_status = sn_coap_parser_options_parse_multiple_options(packet_data_pptr,
            	                                                                   options_count - i,
            	                                                                   &previous_option_number,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->location_query_ptr,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->location_query_len,
            	                                                                   COAP_OPTION_LOCATION_QUERY,
            	                                                                   option_number_len);
                if (ret_status >= 0)
                {
                    i += (ret_status - 1); /* i += is because possible several Options are handled by sn_coap_parser_options_parse_uri_path() */
                }
                else
                {
                    return -1;
                }

                break;

            case COAP_OPTION_URI_PATH:
            	if(dst_coap_msg_ptr->uri_path_ptr)
            		return -1;
                /* Uri-Path is managed independently because User gives Uri-Path in one character table */
            	ret_status = sn_coap_parser_options_parse_multiple_options(packet_data_pptr,
            	                                                                   options_count - i,
            	                                                                   &previous_option_number,
            	                                                                   &dst_coap_msg_ptr->uri_path_ptr,
            	                                                                   &dst_coap_msg_ptr->uri_path_len,
            	                                                                   COAP_OPTION_URI_PATH,
            	                                                                   option_number_len);
                if (ret_status >= 0)
                {
                    i += (ret_status - 1); /* i += is because possible several Options are handled by sn_coap_parser_options_parse_uri_path() */
                }
                else
                {
                    return -1;
                }

                break;

            case COAP_OPTION_OBSERVE:
            	if((option_number_len > 2) || dst_coap_msg_ptr->options_list_ptr->observe_ptr)
            		return -1;

            	dst_coap_msg_ptr->options_list_ptr->observe = 1;	//todo: COAP12 - is this needed somewhere, seems like not

            	if(option_number_len)
            	{

					dst_coap_msg_ptr->options_list_ptr->observe_len = option_number_len;

					dst_coap_msg_ptr->options_list_ptr->observe_ptr = sn_coap_malloc(option_number_len);

					if (dst_coap_msg_ptr->options_list_ptr->observe_ptr == NULL)
					{
						return -1;
					}

					memcpy(dst_coap_msg_ptr->options_list_ptr->observe_ptr, *packet_data_pptr, option_number_len);

            	}

                break;

            case COAP_OPTION_TOKEN:
            	if((option_number_len > 8) || dst_coap_msg_ptr->token_ptr)
            		return -1;
                dst_coap_msg_ptr->token_len = option_number_len;

                dst_coap_msg_ptr->token_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->token_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->token_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_URI_QUERY:
            	if(dst_coap_msg_ptr->options_list_ptr->uri_query_ptr)
            		return -1;
            	ret_status = sn_coap_parser_options_parse_multiple_options(packet_data_pptr,
            	                                                                   options_count - i,
            	                                                                   &previous_option_number,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->uri_query_ptr,
            	                                                                   &dst_coap_msg_ptr->options_list_ptr->uri_query_len,
            	                                                                   COAP_OPTION_URI_QUERY,
            	                                                                   option_number_len);

				if (ret_status >= 0)
				{
					i += (ret_status - 1); /* i += is because possible several Options are handled by sn_coap_parser_options_parse_uri_path() */
				}
				else
				{
					return -1;
				}

				break;

            case COAP_OPTION_BLOCK2:
            	if((option_number_len > 4) || dst_coap_msg_ptr->options_list_ptr->block2_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->block2_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->block2_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->block2_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->block2_ptr, *packet_data_pptr, option_number_len);

                break;

            case COAP_OPTION_BLOCK1:
            	if((option_number_len > 4) || dst_coap_msg_ptr->options_list_ptr->block1_ptr)
            		return -1;
                dst_coap_msg_ptr->options_list_ptr->block1_len = option_number_len;

                dst_coap_msg_ptr->options_list_ptr->block1_ptr = sn_coap_malloc(option_number_len);

                if (dst_coap_msg_ptr->options_list_ptr->block1_ptr == NULL)
                {
                    return -1;
                }

                memcpy(dst_coap_msg_ptr->options_list_ptr->block1_ptr, *packet_data_pptr, option_number_len);

                break;
        }

        /* If not Uri-Path option because Uri-Path option is handled independently in own function */
        if (option_number != COAP_OPTION_URI_PATH && option_number != COAP_OPTION_URI_QUERY && option_number != COAP_OPTION_LOCATION_PATH && option_number != COAP_OPTION_LOCATION_QUERY)
        {
            (*packet_data_pptr) += option_number_len;
        }
    }

    return 0;
}


/**
 * \fn static int8_t sn_coap_parser_options_parse_multiple_options(uint8_t **packet_data_pptr, uint8_t options_count_left, uint8_t *previous_option_number_ptr, uint8_t **dst_pptr,
 * 																	uint16_t *dst_len_ptr, sn_coap_option_numbers_e option, uint16_t option_number_len)
 *
 * \brief Parses CoAP message's Uri-query options
 *
 * \param **packet_data_pptr is source for Packet data to be parsed to CoAP message
 *
 * \param *dst_coap_msg_ptr is destination for parsed CoAP message
 *
 * \param options_count_left tells how many options are unhandled in Packet data
 *
 * \param *previous_option_number_ptr is pointer to used and returned previous Option number
 *
 * \return Return value is count of Uri-query optios parsed. In failure case -1 is returned.
*/
SN_MEM_ATTR_COAP_PARSER_FUNC
static int8_t sn_coap_parser_options_parse_multiple_options(uint8_t **packet_data_pptr,
                                                    uint8_t options_count_left,
                                                    uint8_t *previous_option_number_ptr,
                                                    uint8_t **dst_pptr,
                                                    uint16_t *dst_len_ptr,
                                                    sn_coap_option_numbers_e option,
                                                    uint16_t option_number_len)
{
    uint16_t    uri_query_needed_heap       = sn_coap_parser_options_count_needed_memory_multiple_option(*packet_data_pptr, options_count_left, *previous_option_number_ptr, option, option_number_len);
    uint8_t    *temp_parsed_uri_query_ptr   = NULL;
    uint8_t     returned_option_counter     = 0;

    if(uri_query_needed_heap == 0)
    	return -1;

    *dst_pptr = sn_coap_malloc(uri_query_needed_heap);

    if (*dst_pptr == NULL)
    {
        return -1;
    }

    *dst_len_ptr = uri_query_needed_heap;

    temp_parsed_uri_query_ptr = *dst_pptr;

    *previous_option_number_ptr = *previous_option_number_ptr + option;

    /* Loop all Uri-Query options */
    while (options_count_left > 0)
    {
        /* Check if this is first Uri-Query option */
        if (returned_option_counter > 0)
        {
            /* Uri-Query is modified to following format: temp1'\0'temp2'\0'temp3 i.e.  */
            /* Uri-Path is modified to following format: temp1\temp2\temp3 i.e.  */
        	if(option == COAP_OPTION_URI_QUERY || option == COAP_OPTION_LOCATION_QUERY)
            	memset(temp_parsed_uri_query_ptr, '&', 1);
            else if(option == COAP_OPTION_URI_PATH || option == COAP_OPTION_LOCATION_PATH)
            	memset(temp_parsed_uri_query_ptr, '/', 1);

            temp_parsed_uri_query_ptr++;
        }

        returned_option_counter++;

        (*packet_data_pptr)++;

        if(((temp_parsed_uri_query_ptr - *dst_pptr) + option_number_len) > uri_query_needed_heap)
        	return -1;

        memcpy(temp_parsed_uri_query_ptr, *packet_data_pptr, option_number_len);

        (*packet_data_pptr) += option_number_len;
        temp_parsed_uri_query_ptr += option_number_len;

        if((**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT) != 0)
        {
            return returned_option_counter;
        }

        option_number_len = (**packet_data_pptr & 0x0F);
        if(option_number_len == 15)
        	option_number_len = sn_coap_parser_option_number_len_parse(packet_data_pptr);

        options_count_left--;
    }

    return returned_option_counter;
}




/**
 * \fn static uint16_t sn_coap_parser_options_count_needed_memory_multiple_option(uint8_t *packet_data_ptr, uint8_t options_count_left, uint8_t previous_option_number, sn_coap_option_numbers_e option, uint16_t option_number_len)
 *
 * \brief Counts needed memory for uri query option
 *
 * \param *packet_data_ptr is start of source for Packet data to be parsed to CoAP message
 *
 * \param options_count_left tells how many options are unhandled in Packet data
 *
 * \param previous_option_number is previous Option number
 *
 * \param sn_coap_option_numbers_e option option number to be calculated
 *
 * \param uint16_t option_number_len length of the first option part
 */
SN_MEM_ATTR_COAP_PARSER_FUNC
static uint16_t sn_coap_parser_options_count_needed_memory_multiple_option(uint8_t *packet_data_ptr,
                                                                    uint8_t options_count_left,
                                                                    uint8_t previous_option_number, sn_coap_option_numbers_e option,
                                                                    uint16_t option_number_len)
{
    uint16_t ret_value              = 0;
    uint8_t **packet_data_pptr 		= &packet_data_ptr;


    /* Loop all Uri-Query options */
    while (options_count_left > 0)
    {
    	*packet_data_pptr += 1;

        if(option == COAP_OPTION_LOCATION_PATH && option_number_len > 255)
        	return 0;
        if(option == COAP_OPTION_URI_PATH && option_number_len > 255)
        	return 0;
        if(option == COAP_OPTION_URI_QUERY && option_number_len > 255)
        	return 0;
        if(option == COAP_OPTION_LOCATION_QUERY && option_number_len > 255)
        	return 0;

        *packet_data_pptr += option_number_len;
        ret_value += option_number_len + 1; /* + 1 is for separator */

        if((**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT) != 0)
        {
            if(ret_value != 0)
            	return (ret_value - 1); /* -1 because last Part path does not include separator */
            else
            	return 0;
        }

        option_number_len = (**packet_data_pptr & 0x0F);

		if (option_number_len == 15)
		{
			option_number_len = sn_coap_parser_option_number_len_parse(packet_data_pptr);
			*packet_data_pptr += 1;
		}



        options_count_left--;
    }

    if(ret_value != 0)
    	return (ret_value - 1); /* -1 because last Part path does not include separator */
    else
    	return 0;
}

/**
 * \fn static void sn_coap_parser_payload_parse(uint16_t packet_data_len, uint8_t *packet_data_ptr, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr)
 *
 * \brief Parses CoAP message's Payload part from given Packet data
 *
 * \param packet_data_len is length of given Packet data to be parsed to CoAP message
 *
 * \param *packet_data_ptr is start of source for Packet data to be parsed to CoAP message
 *
 * \param **packet_data_pptr is source for Packet data to be parsed to CoAP message
 *
 * \param *dst_coap_msg_ptr is destination for parsed CoAP message
 *****************************************************************************/
SN_MEM_ATTR_COAP_PARSER_FUNC
static void sn_coap_parser_payload_parse(uint16_t packet_data_len,
                                         uint8_t *packet_data_ptr,
                                         uint8_t **packet_data_pptr,
                                         sn_coap_hdr_s *dst_coap_msg_ptr)
{
    /* If there is payload */
	if((*packet_data_pptr - packet_data_ptr) < packet_data_len)
	{
	    /* Parse Payload length */
		dst_coap_msg_ptr->payload_len = packet_data_len - (*packet_data_pptr - packet_data_ptr);

		/* Parse Payload by setting CoAP message's payload_ptr to point Payload in Packet data */
		dst_coap_msg_ptr->payload_ptr = *packet_data_pptr;
	}

}

/**
 * \fn uint16_t sn_coap_parser_option_jump_parse(uint8_t **packet_data_pptr)
 *
 * \brief Parses CoAP message's option jump
 *
 * \param uint8_t **packet_data_pptr is pointer to packet data pointer
 *
 * \return parsed option number
 *****************************************************************************/
SN_MEM_ATTR_COAP_PARSER_FUNC
uint16_t sn_coap_parser_option_jump_parse(uint8_t **packet_data_pptr)
{
	uint16_t option_number = 0;

	if(((**packet_data_pptr) & 0x0F) == 1)
	{
		*packet_data_pptr += 1;
		option_number = 15;
	}
	else if(((**packet_data_pptr) & 0x0F) == 2)
	{
		*packet_data_pptr += 1;
		option_number = (((**packet_data_pptr) + 2) * 8);
		*packet_data_pptr += 1;
	}
	else if(((**packet_data_pptr) & 0x0F) == 3)
	{
		*packet_data_pptr += 1;
		option_number = (((uint16_t)(**packet_data_pptr) + 258) * 8);
		*packet_data_pptr += 2;
	}

	return option_number;

}

/**
 * \fn uint16_t sn_coap_parser_option_number_len_parse(uint8_t **packet_data_pptr)
 *
 * \brief Parses CoAP message's length field, if > 14
 *
 * \param uint8_t **packet_data_pptr is pointer to packet data pointer
 *
 * \return parsed option length
 *****************************************************************************/
SN_MEM_ATTR_COAP_PARSER_FUNC
uint16_t sn_coap_parser_option_number_len_parse(uint8_t **packet_data_pptr)
{
	uint16_t option_length = 0;
	*packet_data_pptr += 1;
	if((**packet_data_pptr) != 0xff)
		return (**packet_data_pptr) + 15;

	*packet_data_pptr += 1;
	if((**packet_data_pptr) != 0xff)
		return (**packet_data_pptr) + 270;

	*packet_data_pptr += 1;
	if((**packet_data_pptr) != 0xff)
		return (**packet_data_pptr) + 525;

	*packet_data_pptr += 1;
	if((**packet_data_pptr) != 0xff)
		return (**packet_data_pptr) + 780;

	return option_length;
}

/**
 * \fn void sn_coap_packet_debug(sn_coap_hdr_s *coap_packet_ptr)
 *
 * \brief Parses CoAP message and prints parts for debugging
 *
 * \param *coap_packet_ptr Pointer to the CoAP message to debug
 *
 *****************************************************************************/
SN_MEM_ATTR_COAP_PARSER_FUNC
void sn_coap_packet_debug(sn_coap_hdr_s *coap_packet_ptr)
{
#ifdef HAVE_DEBUG
	switch (coap_packet_ptr->msg_type)
	{
		case COAP_MSG_TYPE_CONFIRMABLE:
            printf("con ");
            break;

		case COAP_MSG_TYPE_NON_CONFIRMABLE:
            printf("non ");
            break;

		case COAP_MSG_TYPE_ACKNOWLEDGEMENT:
            printf("ack ");
            break;

		case COAP_MSG_TYPE_RESET:
            printf("rst ");
            break;
	}

	switch (coap_packet_ptr->msg_code)
	{
        case COAP_MSG_CODE_EMPTY:
            printf("NO CODE ");
            break;

        case COAP_MSG_CODE_REQUEST_GET:
            printf("GET ");
            break;

        case COAP_MSG_CODE_REQUEST_POST:
            printf("POST ");
            break;

        case COAP_MSG_CODE_REQUEST_PUT:
            printf("PUT ");
            break;

        case COAP_MSG_CODE_REQUEST_DELETE:
            printf("DELETE ");
            break;

        case COAP_MSG_CODE_RESPONSE_CREATED:
            printf("2.01 Created ");
            break;

        case COAP_MSG_CODE_RESPONSE_DELETED:
            printf("2.02 Deleted ");
            break;

        case COAP_MSG_CODE_RESPONSE_VALID:
            printf("2.03 Valid ");
            break;

        case COAP_MSG_CODE_RESPONSE_CHANGED:
            printf("2.04 Changed ");
            break;

        case COAP_MSG_CODE_RESPONSE_CONTENT:
            printf("2.05 Content ");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
            printf("4.00 Bad Request ");
            break;

        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
            printf("4.01 Unauthorized ");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
            printf("4.02 Bad Option ");
            break;

        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
            printf("4.03 Forbidden ");
            break;

        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
            printf("4.04 Not Found ");
            break;

        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
            printf("4.05 Method Not Allowed ");
            break;

        case COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE:
            printf("4.06 Response Not Acceptable");
            break;

        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
            printf("4.08 Request Entity Incomplete ");
            break;

        case COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED:
            printf("4.12 Response Precondition Failed");
            break;

        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
            printf("4.13 Request Entity Too Large ");
            break;

        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT:
            printf("4.15 Unsupported Media Type ");
            break;

        case COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR:
            printf("5.00 Internal Server Error ");
            break;

        case COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED:
            printf("5.01 Not Implemented ");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_GATEWAY:
            printf("5.02 Bad Gateway ");
            break;

        case COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE:
            printf("5.03 Service Unavailable ");
            break;

        case COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT:
            printf("5.04 Gateway Timeout ");
            break;

        case COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED:
            printf("5.05 Proxying Not Supported ");
            break;

        default:
            printf("UNKNOWN CODE ");
            break;
    }

    printf("mid=%i ", (int)(coap_packet_ptr->msg_id));

	if (coap_packet_ptr->uri_path_ptr)
	{
		int i;
		printf("/");
		for (i=0; i < coap_packet_ptr->uri_path_len; i++) printf("%c", (char)(coap_packet_ptr->uri_path_ptr[i]));
		if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->uri_query_ptr)
		{
			printf("?");
			for (i=0; i < coap_packet_ptr->options_list_ptr->uri_query_len; i++) printf("%c", (char)(coap_packet_ptr->options_list_ptr->uri_query_ptr[i]));
		}
		printf(" ");
    }

	if (coap_packet_ptr->token_ptr)
	{
		int i;
		printf("token=0x");
		for (i=0; i < coap_packet_ptr->token_len; i++) printf("%02x", (unsigned char)(coap_packet_ptr->token_ptr[i]));
		printf(" ");
	}

    if (coap_packet_ptr->content_type_ptr)
    {
    	switch (coap_packet_ptr->content_type_ptr[0])
    	{
        	case COAP_CT_TEXT_PLAIN:
        		printf("text/plain ");
        		break;

        	case COAP_CT_LINK_FORMAT:
        		printf("application/link-format ");
        		break;

        	case COAP_CT_XML:
        		printf("application/xml ");
        		break;

        	case COAP_CT_OCTET_STREAM:
        		printf("application/octet-stream ");
        		break;

        	case COAP_CT_EXI:
        	    printf("application/exi ");
        	    break;

        	case COAP_CT_JSON:
        	     printf("application/json ");
        	     break;
        default:
        	printf("uknown type (%i) ", (int)(coap_packet_ptr->content_type_ptr[0]));
        	break;

    	}
    }

	if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->location_path_ptr)
	{
		printf("Location: /");
		int i;
		for (i=0; i < coap_packet_ptr->options_list_ptr->location_path_len; i++) printf("%c", (char)(coap_packet_ptr->options_list_ptr->location_path_ptr[i]));
		printf(" ");
	}

    if (coap_packet_ptr->payload_ptr)
    {
		int i;
		printf("'");
		for (i=0; i < coap_packet_ptr->payload_len; i++)
			printf("%c", *(coap_packet_ptr->payload_ptr + i));
		printf("' ");
    }

	printf("\n");
#endif
}
