/**
 * \file sn_coap_protocol_ietf_draft_12.c
 *
 * \brief CoAP Protocol implementation
 *
 * Functionality: CoAP Protocol
 *
 *  Created on: Jul 19, 2011
 *      Author: tero
 *
 * \note Supports draft-ietf-core-coap-12
 */


/* * * * * * * * * * * * * * */
/* * * * INCLUDE FILES * * * */
/* * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h> /* For libary malloc() */
#include <string.h> /* For memset() and memcpy() */
#ifndef REAL_EMBEDDED
#include <time.h>
#endif

#include "nsdl_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header_ietf_draft_12.h"
#include "sn_coap_protocol_ietf_draft_12.h"
#include "sn_linked_list.h"

/* * * * * * * * * * * * * * * * * * * * */
/* * * * LOCAL FUNCTION PROTOTYPES * * * */
/* * * * * * * * * * * * * * * * * * * * */


static void                  sn_coap_protocol_linked_list_ack_info_store(uint16_t msg_id, uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr);
static int32_t               sn_coap_protocol_linked_list_ack_info_search(uint16_t msg_id, uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr);
static void                  sn_coap_protocol_linked_list_ack_info_remove(uint16_t msg_id, sn_nsdl_addr_s *addr_ptr);
static void                  sn_coap_protocol_linked_list_ack_info_remove_old_ones();
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */
static void                  sn_coap_protocol_linked_list_duplication_info_store(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id);
static int8_t                sn_coap_protocol_linked_list_duplication_info_search(sn_nsdl_addr_s *scr_addr_ptr, uint16_t msg_id);
static void                  sn_coap_protocol_linked_list_duplication_info_remove(uint8_t *scr_addr_ptr, uint16_t port, uint16_t msg_id);
static void                  sn_coap_protocol_linked_list_duplication_info_remove_old_ones(void);
#endif
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
static void                  sn_coap_protocol_linked_list_blockwise_msg_remove_current();
static void                  sn_coap_protocol_linked_list_blockwise_payload_store(sn_nsdl_addr_s *addr_ptr, uint16_t stored_payload_len, uint8_t *stored_payload_ptr);
static uint8_t              *sn_coap_protocol_linked_list_blockwise_payload_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t *payload_length);
static void                  sn_coap_protocol_linked_list_blockwise_payload_remove_oldest();
static uint16_t              sn_coap_protocol_linked_list_blockwise_payloads_get_len(sn_nsdl_addr_s *src_addr_ptr);
static void                  sn_coap_protocol_linked_list_blockwise_remove_old_data(void);
static sn_coap_hdr_s 		*sn_coap_handle_blockwise_message(sn_nsdl_addr_s *src_addr_ptr, sn_coap_hdr_s *received_coap_msg_ptr);
static uint8_t 				 sn_coap_convert_block_size(uint16_t block_size);
static sn_coap_hdr_s 		*sn_coap_protocol_copy_header(sn_coap_hdr_s *source_header_ptr);
#endif
#if SN_COAP_RESENDING_MAX_COUNT
static sn_nsdl_transmit_s   *sn_coap_protocol_build_msg(void *src_msg_ptr);
#endif
#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message resending is not used at all, this part of code will not be compiled */
static void                  sn_coap_protocol_linked_list_send_msg_store(sn_nsdl_addr_s *dst_addr_ptr, uint16_t send_packet_data_len, uint8_t *send_packet_data_ptr, uint32_t sending_time);
static sn_nsdl_transmit_s   *sn_coap_protocol_linked_list_send_msg_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id);
static void                  sn_coap_protocol_linked_list_send_msg_remove(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id);
static int8_t                sn_coap_protocol_allocate_mem_for_msg(sn_nsdl_addr_s *dst_addr_ptr, uint16_t packet_data_len, void *msg_ptr);
static void                  sn_coap_protocol_release_allocated_send_msg_mem(coap_send_msg_s *freed_send_msg_ptr);
#endif
static void 				 coap_protocol_free_lists(void);

/* * * * * * * * * * * * * * * * * */
/* * * * GLOBAL DECLARATIONS * * * */
/* * * * * * * * * * * * * * * * * */

#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message resending is not used at all, this part of code will not be compiled */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static sn_linked_list_t *global_linked_list_resent_msgs_ptr                 = NULL; /* Active resending messages are stored to this Linked list */
#endif
SN_MEM_ATTR_COAP_PROTOCOL_DECL static sn_linked_list_t *global_linked_list_ack_info_ptr                    = NULL; /* Message Acknowledgement info is stored to this Linked list */
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static sn_linked_list_t *global_linked_list_duplication_msgs_ptr            = NULL; /* Messages for duplicated messages detection is stored to this Linked list */
#endif
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwise is not used at all, this part of code will not be compiled */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static sn_linked_list_t *global_linked_list_blockwise_sent_msgs_ptr         = NULL; /* Blockwise message to to be sent is stored to this Linked list */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static sn_linked_list_t *global_linked_list_blockwise_received_payloads_ptr = NULL; /* Blockwise payload to to be received is stored to this Linked list */
#endif

SN_MEM_ATTR_COAP_PROTOCOL_DECL static uint16_t          global_message_id                                  	= 100;  /* Increasing Message ID which is written to CoAP message header in building */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static uint32_t          global_system_time                                 	= 0;    /* System time seconds */

SN_MEM_ATTR_COAP_PROTOCOL_DECL uint16_t 				sn_coap_block_data_size 							= 0;
SN_MEM_ATTR_COAP_PROTOCOL_DECL uint8_t 					sn_coap_resending_buffer_size 						= 0;
SN_MEM_ATTR_COAP_PROTOCOL_DECL uint8_t 					sn_coap_resending_count		 						= 0;
SN_MEM_ATTR_COAP_PROTOCOL_DECL uint8_t					sn_coap_duplication_buffer_size						= 0;

SN_MEM_ATTR_COAP_PROTOCOL_DECL static void              *(*sn_coap_protocol_malloc)(uint16_t)              = NULL; /* Function pointer for used malloc() function */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static void              (*sn_coap_protocol_free)(void*)                    = NULL; /* Function pointer for used free()   function */
SN_MEM_ATTR_COAP_PROTOCOL_DECL static uint8_t 			(*sn_coap_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *) = NULL;


static uint8_t 	resource_path_ptr[]			= {'r','d'};
static uint8_t 	ep_name_parameter_string[]	= {'h','='};
static uint8_t	resource_type_parameter[]	= {'r','t','='};

/**
 * \fn int8_t sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr)
 *
 * \brief Builds RD registrtion request packet
 *
 * \param *coap_hdr_ptr is destination for built Packet data
 * \param *endpoint_info_ptr pointer to struct that contains endpoint info parameters
 *
 * \return Return value 0 given on success. In failure cases:\n
 *          -1 = Failure
 */
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t sn_coap_register(sn_coap_hdr_s *coap_hdr_ptr, registration_info_t *endpoint_info_ptr)
{
	uint8_t *temp_ptr;

	coap_hdr_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;
	coap_hdr_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
	coap_hdr_ptr->msg_id = global_message_id++;

	coap_hdr_ptr->uri_path_len = sizeof(resource_path_ptr);
	coap_hdr_ptr->uri_path_ptr = resource_path_ptr;

	/* Payload copy */
	coap_hdr_ptr->payload_len = endpoint_info_ptr->links_len;
	coap_hdr_ptr->payload_ptr = sn_coap_protocol_malloc(coap_hdr_ptr->payload_len);
	if(!coap_hdr_ptr->payload_ptr)
		return -1;
	memcpy(coap_hdr_ptr->payload_ptr, endpoint_info_ptr->links_ptr, coap_hdr_ptr->payload_len);

	/* Options allocation */
	if(!coap_hdr_ptr->options_list_ptr)
	{
		coap_hdr_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));
		if(!coap_hdr_ptr->options_list_ptr)
		{
			sn_coap_protocol_free(coap_hdr_ptr->payload_ptr);
			return -1;
		}
	}
	memset(coap_hdr_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

	/* Uri query filling */
	coap_hdr_ptr->options_list_ptr->uri_query_len = sizeof(ep_name_parameter_string) + endpoint_info_ptr->endpoint_len +
													sizeof(resource_type_parameter) + endpoint_info_ptr->endpoint_type_len + 1; // + 1 for '&'

	coap_hdr_ptr->options_list_ptr->uri_query_ptr = sn_coap_protocol_malloc(coap_hdr_ptr->options_list_ptr->uri_query_len);
	if(!coap_hdr_ptr->options_list_ptr->uri_query_ptr)
	{
		sn_coap_protocol_free(coap_hdr_ptr->options_list_ptr);
		sn_coap_protocol_free(coap_hdr_ptr->payload_ptr);
		return -1;
	}

	temp_ptr = coap_hdr_ptr->options_list_ptr->uri_query_ptr;

	memcpy(temp_ptr, ep_name_parameter_string, sizeof(ep_name_parameter_string));
	temp_ptr += sizeof(ep_name_parameter_string);

	memcpy(temp_ptr, endpoint_info_ptr->endpoint_ptr, endpoint_info_ptr->endpoint_len);
	temp_ptr += endpoint_info_ptr->endpoint_len;

	*temp_ptr++ = '&';

	memcpy(temp_ptr, resource_type_parameter, sizeof(resource_type_parameter));
	temp_ptr += sizeof(resource_type_parameter);

	memcpy(temp_ptr, endpoint_info_ptr->endpoint_type_ptr, endpoint_info_ptr->endpoint_type_len);
	temp_ptr += endpoint_info_ptr->endpoint_type_len;

	return 0;
}

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
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t 	sn_coap_register_update(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length)
{
	coap_hdr_ptr->msg_code = COAP_MSG_CODE_REQUEST_PUT;
	coap_hdr_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
	coap_hdr_ptr->msg_id = global_message_id++;
	coap_hdr_ptr->uri_path_len = length;
	coap_hdr_ptr->uri_path_ptr = location;

	return 0;
}

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
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t 	sn_coap_deregister(sn_coap_hdr_s *coap_hdr_ptr, uint8_t *location, uint8_t length)
{
	coap_hdr_ptr->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
	coap_hdr_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
	coap_hdr_ptr->msg_id = global_message_id++;
	coap_hdr_ptr->uri_path_len = length;
	coap_hdr_ptr->uri_path_ptr = location;

	return 0;
}

SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t sn_coap_protocol_destroy(void)
{
#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE/* If Message resending is not used at all, this part of code will not be compiled */
	if(global_linked_list_resent_msgs_ptr)
	{
				uint16_t size =  sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);
				uint16_t i = 0;
				coap_send_msg_s*tmp;
				for(i=0;i<size;i++)
				{
					tmp = sn_linked_list_get_first_node(global_linked_list_resent_msgs_ptr);

					if(tmp)
					{
						if(tmp->send_msg_ptr)
						{
							if(tmp->send_msg_ptr->dst_addr_ptr)
							{
								if(tmp->send_msg_ptr->dst_addr_ptr->addr_ptr)
								{
									sn_coap_protocol_free(tmp->send_msg_ptr->dst_addr_ptr->addr_ptr);
									tmp->send_msg_ptr->dst_addr_ptr->addr_ptr = 0;
								}
								if(tmp->send_msg_ptr->dst_addr_ptr->socket_information)
								{
									sn_coap_protocol_free(tmp->send_msg_ptr->dst_addr_ptr->socket_information);
									tmp->send_msg_ptr->dst_addr_ptr->socket_information = 0;
								}
								sn_coap_protocol_free(tmp->send_msg_ptr->dst_addr_ptr);
								tmp->send_msg_ptr->dst_addr_ptr = 0;
							}
							if(tmp->send_msg_ptr->packet_ptr)
							{
								sn_coap_protocol_free(tmp->send_msg_ptr->packet_ptr);
								tmp->send_msg_ptr->packet_ptr = 0;
							}
							sn_coap_protocol_free(tmp->send_msg_ptr);
							tmp->send_msg_ptr = 0;
						}
						sn_linked_list_remove_current_node(global_linked_list_resent_msgs_ptr);
						sn_coap_protocol_free(tmp);
						tmp = 0;
					}
				}

				if(!sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr))
				{
					sn_coap_protocol_free(global_linked_list_resent_msgs_ptr);
					global_linked_list_resent_msgs_ptr = 0;
				}
	}
#endif

	if(global_linked_list_ack_info_ptr)
	{
		uint16_t size =  sn_linked_list_count_nodes(global_linked_list_ack_info_ptr);
		uint16_t i = 0;
		coap_ack_info_s*tmp;

		for(i=0;i<size;i++)
		{
			tmp = sn_linked_list_get_first_node(global_linked_list_ack_info_ptr);

			if(tmp)
			{
				if(tmp->token_ptr)
				{
					sn_coap_protocol_free(tmp->token_ptr);
					tmp->token_ptr = 0;
				}
				if(tmp->addr_ptr)
				{
					sn_coap_protocol_free(tmp->addr_ptr);
					tmp->addr_ptr = 0;
				}
				sn_coap_protocol_free(tmp);
				tmp = 0;
			}
		}

		if(!sn_linked_list_count_nodes(global_linked_list_ack_info_ptr))
		{
			sn_coap_protocol_free(global_linked_list_ack_info_ptr);
			global_linked_list_ack_info_ptr = 0;
		}
	}

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */
	if(global_linked_list_duplication_msgs_ptr)
	{

	}
#endif

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwise is not used at all, this part of code will not be compiled */
	if(global_linked_list_blockwise_sent_msgs_ptr)
	{

	}
	if(global_linked_list_blockwise_received_payloads_ptr)
	{

	}
#endif
return 0;
}


SN_MEM_ATTR_COAP_PROTOCOL_FUNC
void coap_protocol_free_lists(void)
{
#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
	if(NULL != global_linked_list_resent_msgs_ptr)
	{
		sn_linked_list_free(global_linked_list_resent_msgs_ptr);
		global_linked_list_resent_msgs_ptr = NULL;
	}
#endif
	if(NULL != global_linked_list_ack_info_ptr)
	{
		sn_linked_list_free(global_linked_list_ack_info_ptr);
		global_linked_list_ack_info_ptr = NULL;
	}
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
	if(NULL != global_linked_list_duplication_msgs_ptr)
	{
		sn_linked_list_free(global_linked_list_duplication_msgs_ptr);
		global_linked_list_duplication_msgs_ptr = NULL;
	}
#endif
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
	if(NULL != global_linked_list_blockwise_sent_msgs_ptr)
	{
		sn_linked_list_free(global_linked_list_blockwise_sent_msgs_ptr);
		global_linked_list_blockwise_sent_msgs_ptr = NULL;
	}
	if(NULL != global_linked_list_blockwise_received_payloads_ptr)
	{
		sn_linked_list_free(global_linked_list_blockwise_received_payloads_ptr);
		global_linked_list_blockwise_received_payloads_ptr = NULL;
	}
#endif

}

/**************************************************************************//**
 * \fn int8_t sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
		uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *))
 *
 * \brief Initializes CoAP Protocol part
 *
 * \param *used_malloc_func_ptr is function pointer for used malloc() function.
 *        If set to NULL, CoAP Protocol part uses standard C-library malloc() function.
 *
 * \param *used_free_func_ptr is function pointer for used free() function.
 *        If set to NULL, CoAP Protocol part uses standard C-library free() function.
 *
 * \param *used_tx_callback_ptr function callback pointer to tx function for sending coap messages
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t sn_coap_protocol_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*),
		uint8_t (*used_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *))
{
    /* * * Handling malloc() * * */
    if (used_malloc_func_ptr != NULL)
        sn_coap_protocol_malloc = used_malloc_func_ptr;
    else
    	return -1;

    /* * * Handling free() * * */
    if (used_free_func_ptr != NULL)
        sn_coap_protocol_free = used_free_func_ptr;
    else
    	return -1;

    /* * * Handle tx callback * * */
    if(used_tx_callback_ptr != NULL)
    	sn_coap_tx_callback = used_tx_callback_ptr;
    else
    	return -1;

    sn_linked_list_init(sn_coap_protocol_malloc, sn_coap_protocol_free);

#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message resending is not used at all, this part of code will not be compiled */

    /* * * * Create Linked list for storing active resending messages  * * * */
    sn_coap_resending_buffer_size = SN_COAP_RESENDING_BUFFER_MAX_SIZE;
    sn_coap_resending_count = SN_COAP_RESENDING_MAX_COUNT;
    sn_coap_block_data_size = SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE;

    /* Check that Linked list is not already created */
    if (global_linked_list_resent_msgs_ptr == NULL)
    {
        global_linked_list_resent_msgs_ptr = sn_linked_list_create();

        if(global_linked_list_resent_msgs_ptr == NULL)
        {
        	coap_protocol_free_lists();
        	return (-1);
        }

    }

#endif /* SN_COAP_RESENDING_MAX_COUNT */

    /* * * * Create Linked list for storing Acknowledgement info, if not already created * * * */
    if (global_linked_list_ack_info_ptr == NULL)
    {
        global_linked_list_ack_info_ptr = sn_linked_list_create();

        if(global_linked_list_ack_info_ptr == NULL)
        {
        	coap_protocol_free_lists();
        	return (-1);
        }

    }

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */
    /* * * * Create Linked list for storing Duplication info * * * */
    sn_coap_duplication_buffer_size = SN_COAP_DUPLICATION_MAX_MSGS_COUNT;

    /* Check that Linked list is not already created */
    if (global_linked_list_duplication_msgs_ptr == NULL)
    {
        global_linked_list_duplication_msgs_ptr = sn_linked_list_create();

        if(global_linked_list_duplication_msgs_ptr == NULL)
        {
        	coap_protocol_free_lists();
        	return (-1);
        }
    }
#endif

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */

    /* * * * Create Linked list for storing sent blockwise messages, if not already created  * * * */
    if (global_linked_list_blockwise_sent_msgs_ptr == NULL)
    {
        global_linked_list_blockwise_sent_msgs_ptr = sn_linked_list_create();

        if(global_linked_list_blockwise_sent_msgs_ptr == NULL)
        {
        	coap_protocol_free_lists();
        	return (-1);
        }

    }

    /* * * * Create Linked list for storing received blockwise payload, if not already created * * * */
    if (global_linked_list_blockwise_received_payloads_ptr == NULL)
    {
        global_linked_list_blockwise_received_payloads_ptr = sn_linked_list_create();

        if(global_linked_list_blockwise_received_payloads_ptr == NULL)
        {
        	coap_protocol_free_lists();
        	return (-1);
        }
    }
#endif /* SN_COAP_RESENDING_MAX_COUNT */

    /* Randomize global message ID */
#ifndef REAL_EMBEDDED
   	srand(time(NULL));
#endif
    {
	    uint8_t random_number = rand();
	    global_message_id = 100 + random_number;
    }

	return 0;
}

/**************************************************************************//**
 * \fn int8_t sn_coap_protocol_set_block_size(uint16_t block_size)
 *
 * \brief Sets block size
 *
 * \param uint16_t block_size maximum size of CoAP payload. Valid sizes are 16, 32, 64, 128, 256, 512 and 1024 bytes
 * \return 	0 = success
 * 			-1 = failure
 */

int8_t sn_coap_protocol_set_block_size(uint16_t block_size)
{
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
	switch(block_size)
	{
	case 0:
	case 16:
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
		sn_coap_block_data_size = block_size;
		return 0;
	default:
		break;
	}
#endif
	return -1;

}

/**************************************************************************//**
 * \fn int8_t sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count)
 *
 * \brief Sets max number of messages saved for message duplication checks
 *
 * \param uint8_t message_count max number of messages saved for duplicate control
 * \return 	0 = success
 * 			-1 = failure
 */

int8_t sn_coap_protocol_set_duplicate_buffer_size(uint8_t message_count)
{
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
	if(message_count <= SN_COAP_MAX_ALLOWED_DUPLICATION_MESSAGE_COUNT)
	{
		sn_coap_duplication_buffer_size = message_count;
		return 0;
	}
#endif
	return -1;
}

/**************************************************************************//**
 * \fn int8_t sn_coap_protocol_set_max_saved_duplicate_messages(uint8_t message_count)
 *
 * \brief Sets max number of messages saved for message duplication checks
 *
 * \param uint8_t message_count max number of messages saved for duplicate control
 * \return 	0 = success
 * 			-1 = failure
 */

int8_t sn_coap_protocol_set_retransmission(uint8_t resending_count, uint8_t buffer_size)
{
#if SN_COAP_RESENDING_MAX_COUNT && SN_COAP_RESENDING_MAX_COUNT
	if(resending_count <= SN_COAP_MAX_ALLOWED_RESENDING_COUNT && resending_count <= SN_COAP_MAX_ALLOWED_RESENDING_BUFF_SIZE)
	{
		sn_coap_resending_count = resending_count;
		sn_coap_resending_buffer_size = buffer_size;
		return 0;
	}
#endif

	return -1;
}

/**************************************************************************//**
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
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int16_t sn_coap_protocol_build(sn_nsdl_addr_s *dst_addr_ptr,
                      uint8_t *dst_packet_data_ptr,
                      sn_coap_hdr_s *src_coap_msg_ptr)
{
    int32_t  message_id           = -3;
    int16_t  byte_count_built     = 0;
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
    uint16_t original_payload_len = 0;
#endif

    /* * * * Check given pointers  * * * */
    if (dst_addr_ptr == NULL || dst_addr_ptr->addr_ptr == NULL ||
        dst_packet_data_ptr == NULL ||
        src_coap_msg_ptr == NULL)
    {
        return -2;
    }

    /* Check if built Message type is Reset message or Message code is some of response messages */
    /* (for these messages CoAP writes same Message ID which was stored earlier from request message) */
    if (src_coap_msg_ptr->msg_type == COAP_MSG_TYPE_RESET || src_coap_msg_ptr->msg_code >= COAP_MSG_CODE_RESPONSE_CREATED)
    {
        /* Check if there is Token option in built CoAP message */
        /* (only these messages can be acknowledged because Token option is used as key for stored messages) */
			if (src_coap_msg_ptr->token_ptr != NULL)
			{
				/* Search Message ID from Linked list with Token option and Address as key */
				message_id = sn_coap_protocol_linked_list_ack_info_search(src_coap_msg_ptr->msg_id, src_coap_msg_ptr->token_len,
																		  src_coap_msg_ptr->token_ptr, dst_addr_ptr);
			}
			else
			{
				message_id = sn_coap_protocol_linked_list_ack_info_search(src_coap_msg_ptr->msg_id, 0, NULL, dst_addr_ptr);
			}

            /* If Message ID found */
            if (message_id >= 0)
            {
                /* * * * Manage received CoAP message acknowledgement  * * * */
                /* Piggy-backed response message found */

            	/* Client                   Server */

            	/*       ------------------> Confirmable request message (CoAP stores Acknowledgement info to Linked list) */

            	/*       <------------------ THIS IS DONE HERE: Piggy-backed acknowledgement response message (CoAP writes same
                                                                Message ID than was in Request message).
                                                                User has written correct Token option to the response message. */

                if (src_coap_msg_ptr->msg_type != COAP_MSG_TYPE_RESET)
                {
                    /* Now is built Piggy-backed Acknowledgement response message */
                    src_coap_msg_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
                }

                /* Remove Acknowledgement info from Linked list */
                sn_coap_protocol_linked_list_ack_info_remove(src_coap_msg_ptr->msg_id, dst_addr_ptr);
            }
            else if (src_coap_msg_ptr->msg_type == COAP_MSG_TYPE_RESET)
            {
                /* There was not found Message ID for Reset message */
                return -3;
            }
    }

    /* Check if built Message type is else than Acknowledgement or Reset i.e. message type is Confirmable or Non-confirmable */
    /* (for Acknowledgement and  Reset messages is written same Message ID than was in the Request message) */
    if (src_coap_msg_ptr->msg_type != COAP_MSG_TYPE_ACKNOWLEDGEMENT &&
        src_coap_msg_ptr->msg_type != COAP_MSG_TYPE_RESET)
    {
        /* * * * Generate new Message ID and increase it by one  * * * */
		if(0 > message_id)
		{
			message_id = global_message_id;
			global_message_id++;
		}
    }
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */
    else /* Acknowledgement or Reset */
    {
        /* Remove duplication message, if found, from Linked list */
        sn_coap_protocol_linked_list_duplication_info_remove(dst_addr_ptr->addr_ptr, dst_addr_ptr->port, message_id);
    }
#endif

    /* Set message ID to coap Header */
    src_coap_msg_ptr->msg_id = (uint16_t)message_id;

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */

    /* If blockwising needed */
    if ((src_coap_msg_ptr->payload_len > sn_coap_block_data_size) && (sn_coap_block_data_size > 0))
    {
        /* * * * Add Blockwise option to send CoAP message * * */

    	if (src_coap_msg_ptr->options_list_ptr == NULL)
        {
            /* Allocate memory for less used options */
            src_coap_msg_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));

            if (src_coap_msg_ptr->options_list_ptr == NULL)
            {
                return -2;
            }
            memset(src_coap_msg_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
        }


        /* Check if Request message */
        if (src_coap_msg_ptr->msg_code < COAP_MSG_CODE_RESPONSE_CREATED )
        {
            /* Add Blockwise option, use Block1 because Request payload */
            src_coap_msg_ptr->options_list_ptr->block1_len = 1;
            src_coap_msg_ptr->options_list_ptr->block1_ptr = sn_coap_protocol_malloc(1);

            if (src_coap_msg_ptr->options_list_ptr->block1_ptr == NULL)
            {
                sn_coap_protocol_free(src_coap_msg_ptr->options_list_ptr);

                return -2;
            }

            *(src_coap_msg_ptr->options_list_ptr->block1_ptr) = 0x08; 		/* First block  (BLOCK NUMBER, 4 MSB bits) + More to come (MORE, 1 bit) */
            *(src_coap_msg_ptr->options_list_ptr->block1_ptr) |= sn_coap_convert_block_size(sn_coap_block_data_size);

        }
        else /* Response message */
        {
            /* Add Blockwise option, use Block2 because Response payload */
            src_coap_msg_ptr->options_list_ptr->block2_len = 1;
            src_coap_msg_ptr->options_list_ptr->block2_ptr = sn_coap_protocol_malloc(1);

            if (src_coap_msg_ptr->options_list_ptr->block2_ptr == NULL)
            {
                sn_coap_protocol_free(src_coap_msg_ptr->options_list_ptr);
                return -2;
            }

            *(src_coap_msg_ptr->options_list_ptr->block2_ptr) = 0x08; 		/* First block  (BLOCK NUMBER, 4 MSB bits) + More to come (MORE, 1 bit) */
            *(src_coap_msg_ptr->options_list_ptr->block2_ptr) |= sn_coap_convert_block_size(sn_coap_block_data_size);
        }

        /* Store original Payload length */
        original_payload_len = src_coap_msg_ptr->payload_len;

        /* Change Payload length of send message because Payload is blockwised */
        src_coap_msg_ptr->payload_len = sn_coap_block_data_size;
    }

#endif
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * Build Packet data from CoAP message by using CoAP Header builder  * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    src_coap_msg_ptr->msg_id = (uint16_t)message_id;

    byte_count_built = sn_coap_builder(dst_packet_data_ptr, src_coap_msg_ptr);

    if (byte_count_built < 0)
    {
        return byte_count_built;
    }

#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE/* If Message resending is not used at all, this part of code will not be compiled */

    /* Check if built Message type was confirmable, only these messages are resent */
    if (src_coap_msg_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
    {
        /* * * * * * * * * * * * * * * * * * * * * */
        /* * * * Manage CoAP message resending * * */
        /* * * * * * * * * * * * * * * * * * * * * */

        /* Store message to Linked list for resending purposes */
        sn_coap_protocol_linked_list_send_msg_store(dst_addr_ptr, byte_count_built, dst_packet_data_ptr,
                                                    global_system_time + (uint32_t)(RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR));
    }

#endif /* SN_COAP_RESENDING_MAX_COUNT */

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */

    /* If blockwising needed */
    if ((original_payload_len > sn_coap_block_data_size) && (sn_coap_block_data_size > 0))
    {

        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
        /* * * * Manage rest blockwise messages sending by storing them to Linked list * * * */
        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    	coap_blockwise_msg_s *stored_blockwise_msg_ptr;

    	stored_blockwise_msg_ptr = sn_coap_protocol_malloc(sizeof(coap_blockwise_msg_s));
    	if(!stored_blockwise_msg_ptr)
    	{
    		//block paylaod save failed, only first block can be build. Perhaps we should return error.
    		return byte_count_built;
    	}
    	memset(stored_blockwise_msg_ptr, 0, sizeof(coap_blockwise_msg_s));

    	/* Fill struct */
    	stored_blockwise_msg_ptr->timestamp = global_system_time;

    	stored_blockwise_msg_ptr->coap_msg_ptr = sn_coap_protocol_copy_header(src_coap_msg_ptr);

    	stored_blockwise_msg_ptr->coap_msg_ptr->payload_len = original_payload_len;
    	stored_blockwise_msg_ptr->coap_msg_ptr->payload_ptr = sn_coap_protocol_malloc(stored_blockwise_msg_ptr->coap_msg_ptr->payload_len);
    	if(!stored_blockwise_msg_ptr->coap_msg_ptr->payload_ptr)
    	{
    		//block paylaod save failed, only first block can be build. Perhaps we should return error.
    		sn_coap_protocol_free(stored_blockwise_msg_ptr);
    		return byte_count_built;
    	}
    	memcpy(stored_blockwise_msg_ptr->coap_msg_ptr->payload_ptr, src_coap_msg_ptr->payload_ptr, stored_blockwise_msg_ptr->coap_msg_ptr->payload_len);

    	sn_linked_list_add_node(global_linked_list_blockwise_sent_msgs_ptr, stored_blockwise_msg_ptr);
    }

#endif /* SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE */

    /* * * * Return built CoAP message Packet data length  * * * */
    return byte_count_built;
}

/**************************************************************************//**
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
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
sn_coap_hdr_s *sn_coap_protocol_parse(sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
{
    sn_coap_hdr_s   *returned_dst_coap_msg_ptr = NULL;
    coap_version_e   coap_version              = COAP_VERSION_UNKNOWN;
    uint16_t         msg_id                    = 0;
    int8_t           ret_status                = 0;

    /* * * * Check given pointer * * * */
    if (src_addr_ptr == NULL || src_addr_ptr->addr_ptr == NULL ||
        packet_data_ptr == NULL)
    {
        return NULL;
    }

    /* * * * Parse Packet data to CoAP message by using CoAP Header parser * * * */
    returned_dst_coap_msg_ptr = sn_coap_parser(packet_data_len, packet_data_ptr, &coap_version);

    /* Check status of returned pointer */
    if (returned_dst_coap_msg_ptr == NULL)
    {
        /* Memory allocation error in parser */
    	return NULL;
    }

    msg_id = returned_dst_coap_msg_ptr->msg_id;

    /* * * * Check validity of parsed Header values  * * * */
    ret_status = sn_coap_header_validity_check(returned_dst_coap_msg_ptr, coap_version);

    /* If failure in parsed message validity check */
    if (ret_status != 0)
    {
		 /* Release memory of CoAP message */
		sn_coap_parser_release_allocated_coap_msg_mem(returned_dst_coap_msg_ptr);

		/* Return NULL because Header validity check failed */
		return NULL;
    }

#if !SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is used, this part of code will not be compiled */
        /* If blockwising used in received message */
        if (returned_dst_coap_msg_ptr->options_list_ptr != NULL &&
            (returned_dst_coap_msg_ptr->options_list_ptr->block1_ptr != NULL ||
             returned_dst_coap_msg_ptr->options_list_ptr->block2_ptr != NULL))
        {
            /* Set returned status to User */
            returned_dst_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_REJECTED;
            return returned_dst_coap_msg_ptr;
        }
#endif /* !SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE */

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication is used, this part of code will not be compiled */

    /* * * * Manage received CoAP message duplicate detection  * * * */

    /* Check if duplication message detected */
    ret_status = sn_coap_protocol_linked_list_duplication_info_search(src_addr_ptr, msg_id);

    /* If no message duplication detected */
    if (ret_status == -1)
    {
        /* * * No Message duplication: Store received message for detecting later duplication * * */

        /* Get count of stored duplication messages */
        uint16_t stored_duplication_msgs_count = sn_linked_list_count_nodes(global_linked_list_duplication_msgs_ptr);

        /* Check if there is no room to store message for duplication detection purposes */
        if (stored_duplication_msgs_count >= sn_coap_duplication_buffer_size)
        {
            /* Get oldest stored duplication message */
            coap_duplication_info_s *stored_duplication_info_ptr = sn_linked_list_get_last_node(global_linked_list_duplication_msgs_ptr);

            /* Remove oldest stored duplication message for getting room for new duplication message */
            sn_coap_protocol_linked_list_duplication_info_remove(stored_duplication_info_ptr->addr_ptr, stored_duplication_info_ptr->port, stored_duplication_info_ptr->msg_id);
        }

        /* Store Duplication info to Linked list */
        sn_coap_protocol_linked_list_duplication_info_store(src_addr_ptr, msg_id);
    }
    else /* * * Message duplication detected * * */
    {
        /* Set returned status to User */
        returned_dst_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_DUPLICATED_MSG;

        /* Because duplicate message, return with coap_status set */
        return returned_dst_coap_msg_ptr;
    }
#endif


    /*** And here we check if message was block message ***/
    /*** If so, we call own block handling function and ***/
    /*** return to caller.								***/
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE

    if (returned_dst_coap_msg_ptr->options_list_ptr != NULL &&
        (returned_dst_coap_msg_ptr->options_list_ptr->block1_ptr != NULL ||
         returned_dst_coap_msg_ptr->options_list_ptr->block2_ptr != NULL))
    {
    	returned_dst_coap_msg_ptr = sn_coap_handle_blockwise_message(src_addr_ptr, returned_dst_coap_msg_ptr);
    }

    if(!returned_dst_coap_msg_ptr)
    	return NULL;

#endif

    /* Check if received Message type was confirmable */
    if (returned_dst_coap_msg_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
    {
        if (returned_dst_coap_msg_ptr->token_ptr != NULL)
        {
            /* * * * Manage received CoAP message acknowledgement  * * */

            /* Client                   Server */

            /*       ------------------> THIS IS DONE HERE: Confirmable request (CoAP stores Acknowledgement info to Linked list) */

            /*       <------------------ Piggy-backed acknowledgement response message (CoAP writes same Message ID
                                         than was in Request message).
                                         User has written correct Token option to the response message. */

            /* Store message's Acknowledgement info to Linked list */
            sn_coap_protocol_linked_list_ack_info_store(msg_id, returned_dst_coap_msg_ptr->token_len, returned_dst_coap_msg_ptr->token_ptr, src_addr_ptr);
        }
        else
        {
        	sn_coap_protocol_linked_list_ack_info_store(msg_id, 0, NULL, src_addr_ptr);
        }
    }


#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE/* If Message resending is not used at all, this part of code will not be compiled */

    /* Check if received Message type was acknowledgement */
    if (returned_dst_coap_msg_ptr->msg_type == COAP_MSG_TYPE_ACKNOWLEDGEMENT)
    {
        /* * * * Manage CoAP message resending by removing active resending message from Linked list * * */

        /* Get node count i.e. count of active resending messages */
        uint16_t stored_resending_msgs_count = sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);

        /* Check if there is ongoing active message resendings */
        if (stored_resending_msgs_count > 0)
        {
            sn_nsdl_transmit_s *removed_msg_ptr = NULL;

            /* Check if received message was confirmation for some active resending message */

            removed_msg_ptr = sn_coap_protocol_linked_list_send_msg_search(src_addr_ptr, msg_id);

            if (removed_msg_ptr != NULL)
            {
                /* Remove resending message from active message resending Linked list */
                sn_coap_protocol_linked_list_send_msg_remove(src_addr_ptr, msg_id);
            }
        }
    }
#endif /* SN_COAP_RESENDING_MAX_COUNT */

    /* * * * Return parsed CoAP message  * * * */
    return (returned_dst_coap_msg_ptr);
}

/**************************************************************************//**
 * \fn int8_t sn_coap_protocol_exec(uint32_t current_time)
 *
 * \brief Sends CoAP messages from re-sending queue, if there is any.
 * 		  Cleans also old messages from the duplication list and from block receiving list
 *
 *        This function can be called e.g. once in a second but also more frequently.
 *
 *        Messages are sent from following Linked lists:
 *         -global_linked_list_resent_msgs_ptr
 *
 * \param current_time is System time in seconds. This time is
 *        used for message re-sending timing.
 *
 * \return 	0 if success
 * 			-1 if failed
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t sn_coap_protocol_exec(uint32_t current_time)
{
#if SN_COAP_RESENDING_MAX_COUNT
    uint8_t stored_resending_msgs_count;
#endif

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
    /* * * * Remove old blocwise data * * * */
    sn_coap_protocol_linked_list_blockwise_remove_old_data();
#endif

    /* * * * Store current System time * * * */
    global_system_time = current_time;

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
    /* * * * Remove old duplication messages * * * */
    sn_coap_protocol_linked_list_duplication_info_remove_old_ones();
#endif

    /* Remove old Acknowledgement infos */
    sn_coap_protocol_linked_list_ack_info_remove_old_ones();

#if SN_COAP_RESENDING_MAX_COUNT
    /* Check if there is ongoing active message sendings */
    stored_resending_msgs_count = sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);

    if (stored_resending_msgs_count > 0)
    {
        coap_send_msg_s *stored_msg_ptr = sn_linked_list_get_last_node(global_linked_list_resent_msgs_ptr);
        uint8_t          i              = 0;

        for (i = 0; i < stored_resending_msgs_count; i++)
        {
            sn_nsdl_transmit_s *returned_msg_ptr = NULL;

			/* Check if it is time to send this message */
			if (current_time >= stored_msg_ptr->resending_time)
			{
				/* * * Increase Resending counter  * * */
				stored_msg_ptr->resending_counter++;

				/* * * * Allocate and build returned message from stored data  * * * */
				returned_msg_ptr = sn_coap_protocol_build_msg(stored_msg_ptr);

				if (returned_msg_ptr == NULL)
				{
					return -1;
				}

				/* Check if it was last sending of this message */
				if (stored_msg_ptr->resending_counter >= sn_coap_resending_count)
				{
					/* Get message ID from stored sending message */
					uint16_t temp_msg_id = (stored_msg_ptr->send_msg_ptr->packet_ptr[2] << 8);
					temp_msg_id += (uint16_t)stored_msg_ptr->send_msg_ptr->packet_ptr[3];

					/* Remove message from Linked list */
					sn_coap_protocol_linked_list_send_msg_remove(stored_msg_ptr->send_msg_ptr->dst_addr_ptr, temp_msg_id);
				}
				else
				{
					/* * * Count new Resending time  * * */
					stored_msg_ptr->resending_time = current_time + (((uint32_t)(RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR)) <<
																	 stored_msg_ptr->resending_counter);
				}

				/* Send message  */
				sn_coap_tx_callback(returned_msg_ptr->protocol, returned_msg_ptr->packet_ptr,
									returned_msg_ptr->packet_len, returned_msg_ptr->dst_addr_ptr);

				/* Free sent packet */
				sn_coap_builder_release_allocated_send_msg_mem(returned_msg_ptr);
				return 0;
			}

            /* Get next stored sending message from Linked list */
            stored_msg_ptr = sn_linked_list_get_previous_node(global_linked_list_resent_msgs_ptr);
        }
    }

#endif /* SN_COAP_RESENDING_MAX_COUNT */

    return 0;
}

#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message resending is not used at all, this part of code will not be compiled */

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_send_msg_store(sn_nsdl_addr_s *dst_addr_ptr, uint16_t send_packet_data_len, uint8_t *send_packet_data_ptr, uint32_t sending_time)
 *
 * \brief Stores message to Linked list for sending purposes.

 * \param *dst_addr_ptr is pointer to destination address where CoAP message will be sent
 *
 * \param send_packet_data_len is length of Packet data to be stored
 *
 * \param *send_packet_data_ptr is Packet data to be stored
 *
 * \param sending_time is stored sending time
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_send_msg_store(sn_nsdl_addr_s *dst_addr_ptr, uint16_t send_packet_data_len,
                                                        uint8_t *send_packet_data_ptr, uint32_t sending_time)
{

    coap_send_msg_s *stored_msg_ptr              = NULL;
    uint16_t         stored_resending_msgs_count = sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);
    int8_t           ret_status                  = 0;

    /* Check if there is reached limit for active ongoing message resendings */
    if (stored_resending_msgs_count >= sn_coap_resending_buffer_size && sn_coap_block_data_size == 0)
    {
        /* Not allowed to add more Resending messages to Linked list */
        return;
    }

    /* * * * Allocating memory for stored message  * * * */

    /* Allocate memory for structures behind stored sending messages list pointers */

    stored_msg_ptr = sn_coap_protocol_malloc(sizeof(coap_send_msg_s));

    if (stored_msg_ptr == NULL)
    {
        return;
    }

    ret_status = sn_coap_protocol_allocate_mem_for_msg(dst_addr_ptr, send_packet_data_len, stored_msg_ptr);

    if (ret_status != 0)
    {
        sn_coap_protocol_free(stored_msg_ptr);
        sn_coap_protocol_free(stored_msg_ptr->send_msg_ptr);

        return;
    }

    /* * * * Filling fields of stored Resending message  * * * */

    /* Filling of coap_send_msg_s with initialization values */
    stored_msg_ptr->resending_counter = 0;
    stored_msg_ptr->resending_time = sending_time;

    /* Filling of sn_nsdl_transmit_s */
    stored_msg_ptr->send_msg_ptr->protocol = SN_NSDL_PROTOCOL_COAP;
    stored_msg_ptr->send_msg_ptr->packet_len = send_packet_data_len;
    memcpy(stored_msg_ptr->send_msg_ptr->packet_ptr, send_packet_data_ptr, send_packet_data_len);

    /* Filling of sn_nsdl_addr_s */
    stored_msg_ptr->send_msg_ptr->dst_addr_ptr->type = dst_addr_ptr->type;
    stored_msg_ptr->send_msg_ptr->dst_addr_ptr->addr_len = dst_addr_ptr->addr_len;
    memcpy(stored_msg_ptr->send_msg_ptr->dst_addr_ptr->addr_ptr, dst_addr_ptr->addr_ptr, dst_addr_ptr->addr_len);
    stored_msg_ptr->send_msg_ptr->dst_addr_ptr->port = dst_addr_ptr->port;

    /* * * * Storing Resending message to Linked list  * * * */

    sn_linked_list_add_node(global_linked_list_resent_msgs_ptr, stored_msg_ptr);


}

/**************************************************************************//**
 * \fn static sn_nsdl_transmit_s *sn_coap_protocol_linked_list_send_msg_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id)
 *
 * \brief Searches stored resending message from Linked list
 *
 * \param *src_addr_ptr is searching key for searched message
 *
 * \param msg_id is searching key for searched message
 *
 * \return Return value is pointer to found stored resending message in Linked
 *         list or NULL if message not found
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static sn_nsdl_transmit_s *sn_coap_protocol_linked_list_send_msg_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id)
{
    coap_send_msg_s *stored_msg_ptr              = sn_linked_list_get_last_node(global_linked_list_resent_msgs_ptr);
    uint16_t         stored_resending_msgs_count = sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);
    uint8_t          i                           = 0;

    /* Loop all stored resending messages Linked list */
    for (i = 0; i < stored_resending_msgs_count; i++)
    {
        /* Get message ID from stored resending message */
        uint16_t temp_msg_id = (stored_msg_ptr->send_msg_ptr->packet_ptr[2] << 8);
        temp_msg_id += (uint16_t)stored_msg_ptr->send_msg_ptr->packet_ptr[3];

        /* If message's Message ID is same than is searched */
        if (temp_msg_id == msg_id)
        {
            int8_t mem_cmp_result = memcmp(src_addr_ptr->addr_ptr, stored_msg_ptr->send_msg_ptr->dst_addr_ptr->addr_ptr, src_addr_ptr->addr_len);

            /* If message's Source address is same than is searched */
            if (mem_cmp_result == 0)
            {
                /* If message's Source address port is same than is searched */
                if (stored_msg_ptr->send_msg_ptr->dst_addr_ptr->port == src_addr_ptr->port)
                {
                    /* * * Message found, return pointer to that stored resending message * * * */
                    return stored_msg_ptr->send_msg_ptr;
                }
            }
        }

        /* Get next stored message to be searched */
        stored_msg_ptr = sn_linked_list_get_previous_node(global_linked_list_resent_msgs_ptr);
    }

    /* Message not found */
    return NULL;
}
/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_send_msg_remove(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id)
 *
 * \brief Removes stored resending message from Linked list
 *
 * \param *src_addr_ptr is searching key for searched message
 * \param msg_id is searching key for removed message
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_send_msg_remove(sn_nsdl_addr_s *src_addr_ptr, uint16_t msg_id)
{
    coap_send_msg_s *stored_msg_ptr              = sn_linked_list_get_last_node(global_linked_list_resent_msgs_ptr);
    uint16_t         stored_resending_msgs_count = sn_linked_list_count_nodes(global_linked_list_resent_msgs_ptr);
    uint8_t          i                           = 0;

    /* Loop all stored resending messages in Linked list */
    for (i = 0; i < stored_resending_msgs_count; i++)
    {
        /* Get message ID from stored resending message */
        uint16_t temp_msg_id = (stored_msg_ptr->send_msg_ptr->packet_ptr[2] << 8);
        temp_msg_id += (uint16_t)stored_msg_ptr->send_msg_ptr->packet_ptr[3];

        /* If message's Message ID is same than is searched */
        if (temp_msg_id == msg_id)
        {
            int8_t mem_cmp_result = memcmp(src_addr_ptr->addr_ptr, stored_msg_ptr->send_msg_ptr->dst_addr_ptr->addr_ptr, src_addr_ptr->addr_len);

            /* If message's Source address is same than is searched */
            if (mem_cmp_result == 0)
            {
                /* If message's Source address port is same than is searched */
                if (stored_msg_ptr->send_msg_ptr->dst_addr_ptr->port == src_addr_ptr->port)
                {
                    /* * * Message found * * */

                    /* Free memory of stored message */
                    sn_coap_protocol_release_allocated_send_msg_mem(stored_msg_ptr);

                    /* Remove message from Linked list */
                    stored_msg_ptr = sn_linked_list_remove_current_node(global_linked_list_resent_msgs_ptr);

                    return;
                }
            }
        }

        /* Get next stored message to be searched */
        stored_msg_ptr = sn_linked_list_get_previous_node(global_linked_list_resent_msgs_ptr);
    }
}
#endif /* SN_COAP_RESENDING_MAX_COUNT */

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_ack_info_store(uint16_t msg_id, uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr)
 *
 * \brief Stores Acknowledgement info to Linked list
 *
 * \param msg_id is Message ID to be stored
 *
 * \param token_len is length of Token to be stored
 *
 * \param *token_ptr is pointer to Token data to be stored
 *
 * \param *addr_ptr is pointer to Address information to be stored
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_ack_info_store(uint16_t msg_id, uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr)
{
    coap_ack_info_s *stored_ack_info_ptr = NULL;

    /* Remove oldest ack infos from linked list */
    if(sn_linked_list_count_nodes(global_linked_list_ack_info_ptr) >= SN_COAP_ACK_INFO_MAX_COUNT_MESSAGES_SAVED)
    {
    	stored_ack_info_ptr = sn_linked_list_get_last_node(global_linked_list_ack_info_ptr);

    	if(stored_ack_info_ptr)
    	{
    		sn_linked_list_remove_current_node(global_linked_list_ack_info_ptr);

    		if(stored_ack_info_ptr->addr_ptr)
    			sn_coap_protocol_free(stored_ack_info_ptr->addr_ptr);

    		if(stored_ack_info_ptr->token_ptr)
    			sn_coap_protocol_free(stored_ack_info_ptr->token_ptr);

    		sn_coap_protocol_free(stored_ack_info_ptr);

    		stored_ack_info_ptr = NULL;
    	}
    }

    /* * * * Allocating memory for stored Acknowledgement info * * * */

    /* Allocate memory for stored Acknowledgement info's structure */
    stored_ack_info_ptr = sn_coap_protocol_malloc(sizeof(coap_ack_info_s));

    if (stored_ack_info_ptr == NULL)
    {
        return;
    }

    if(token_ptr)
    {

		/* Allocate memory for stored Acknowledgement info's token */
		stored_ack_info_ptr->token_ptr = sn_coap_protocol_malloc(token_len);

		if (stored_ack_info_ptr->token_ptr == NULL)
		{
			sn_coap_protocol_free(stored_ack_info_ptr);

			return;
		}

    }

    /* Allocate memory for stored Acknowledgement info's address */
    stored_ack_info_ptr->addr_ptr = sn_coap_protocol_malloc(addr_ptr->addr_len);

    if (stored_ack_info_ptr->addr_ptr == NULL)
    {
        sn_coap_protocol_free(stored_ack_info_ptr->token_ptr);
        sn_coap_protocol_free(stored_ack_info_ptr);
        return;
    }

    /* * * * Filling fields of stored Acknowledgement info * * * */

    stored_ack_info_ptr->timestamp = global_system_time;
    stored_ack_info_ptr->msg_id = msg_id;
    stored_ack_info_ptr->token_len = token_len;
    if(token_ptr)
    {
    	memcpy(stored_ack_info_ptr->token_ptr, token_ptr, token_len);
    }
    else
    {
    	stored_ack_info_ptr->token_ptr = NULL;
    }
    memcpy(stored_ack_info_ptr->addr_ptr, addr_ptr->addr_ptr, addr_ptr->addr_len);
    stored_ack_info_ptr->port = addr_ptr->port;

    /* * * * Storing Acknowledgement info to Linked list * * * */

    if(sn_linked_list_add_node(global_linked_list_ack_info_ptr, stored_ack_info_ptr) != 0)
    {
    	sn_coap_protocol_free(stored_ack_info_ptr->addr_ptr);
        sn_coap_protocol_free(stored_ack_info_ptr->token_ptr);
        sn_coap_protocol_free(stored_ack_info_ptr);
        return;
    }
}

/**************************************************************************//**
 * \fn static int32_t sn_coap_protocol_linked_list_ack_info_search(uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr)
 *
 * \brief Searches stored Message ID from Linked list
 *
 * \param token_len is length of Token key to be searched
 *
 * \param *token_ptr is pointer to Token key to be searched
 *
 * \param *addr_ptr is pointer to Address key to be searched
 *
 * \return Return value is found Message ID. If Message ID not found, -1 is returned.
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static int32_t sn_coap_protocol_linked_list_ack_info_search(uint16_t msg_id, uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr)
{
    coap_ack_info_s *stored_ack_info_ptr   = sn_linked_list_get_last_node(global_linked_list_ack_info_ptr);
    uint16_t         stored_ack_info_count = sn_linked_list_count_nodes(global_linked_list_ack_info_ptr);
    uint8_t          i                     = 0;
    uint8_t mem_cmp_result = 0;

    if(!addr_ptr)
    	return -1;

    /* Loop all nodes in Linked list for searching Message ID */
    for (i = 0; i < stored_ack_info_count; i++)
    {
        if(!stored_ack_info_ptr)
        	return -1;

        /* If message's Token option is same than is searched */
        if(msg_id == stored_ack_info_ptr->msg_id)
        {
            mem_cmp_result = memcmp(addr_ptr->addr_ptr, stored_ack_info_ptr->addr_ptr, addr_ptr->addr_len);

            /* If message's Source address is same than is searched */
            if (mem_cmp_result == 0)
            {
                /* If message's Source address port is same than is searched */
                if (stored_ack_info_ptr->port == addr_ptr->port)
                {
                	if(stored_ack_info_ptr->token_ptr && token_ptr)
                	{
                		if(stored_ack_info_ptr->token_len == token_len)
                		{
                			mem_cmp_result = memcmp(token_ptr, stored_ack_info_ptr->token_ptr, token_len);

                			if (mem_cmp_result == 0)
                			{
                				/* ACK found and token match */
                				return stored_ack_info_ptr->msg_id;
                			}

                		}
                		return (-2); /* Token does not match */
                	}
                	else
                	{
                		/* * * Correct Acknowledgement info found * * * */
                		return stored_ack_info_ptr->msg_id;
                	}
                }
            }
        }

        /* Get next stored Acknowledgement info to be searched */
        stored_ack_info_ptr = sn_linked_list_get_previous_node(global_linked_list_ack_info_ptr);
    }

    return -1;
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_ack_info_remove(uint8_t token_len, uint8_t *token_ptr, sn_nsdl_addr_s *addr_ptr)
 *
 * \brief Removes stored Acknowledgement info from Linked list
 *
 * \param token_len is length of Token key to be removed
 *
 * \param *token_ptr is pointer to Token key to be removed
 *
 * \param *addr_ptr is pointer to Address key to be removed
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_ack_info_remove(uint16_t msg_id, sn_nsdl_addr_s *addr_ptr)
{
    uint16_t         stored_ack_info_count = sn_linked_list_count_nodes(global_linked_list_ack_info_ptr);
    coap_ack_info_s *stored_ack_info_ptr   = sn_linked_list_get_last_node(global_linked_list_ack_info_ptr);
    uint8_t          i                     = 0;

    if(!addr_ptr)
    	return;

    /* Loop all stored Acknowledgement infos in Linked list */
    for (i = 0; i < stored_ack_info_count; i++)
    {
        if(!stored_ack_info_ptr)
        	return;

        /* If message's Token option is same than is searched */
        if (msg_id == stored_ack_info_ptr->msg_id)
        {

            if (stored_ack_info_ptr->port == addr_ptr->port)
            {

				/* If message's Address is same than is searched */
				if (!memcmp(addr_ptr->addr_ptr, stored_ack_info_ptr->addr_ptr, addr_ptr->addr_len))
				{
					/* * * * Correct Acknowledgement info found, remove it from Linked list * * * */
					stored_ack_info_ptr = sn_linked_list_remove_current_node(global_linked_list_ack_info_ptr);

					/* Free memory of stored Acknowledgement info */
					if(stored_ack_info_ptr->token_ptr)
						sn_coap_protocol_free(stored_ack_info_ptr->token_ptr);

					sn_coap_protocol_free(stored_ack_info_ptr->addr_ptr);
					sn_coap_protocol_free(stored_ack_info_ptr);

					return;
				}

            }

        }

        /* Get next stored message to be searched */
        stored_ack_info_ptr = sn_linked_list_get_previous_node(global_linked_list_ack_info_ptr);
    }
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_ack_info_remove_old_ones(void)
 *
 * \brief Removes old stored Acknowledgement infos from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_ack_info_remove_old_ones(void)
{
    coap_ack_info_s *removed_ack_info_ptr   = sn_linked_list_get_first_node(global_linked_list_ack_info_ptr);

    /* Loop all stored Acknowledgement infos in Linked list */
    while(removed_ack_info_ptr)
    {
        if ((global_system_time - removed_ack_info_ptr->timestamp)  > SN_COAP_ACK_INFO_MAX_TIME_MSGS_STORED)
        {
            /* * * * Old Acknowledgement info found, remove it from Linked list * * * */
            removed_ack_info_ptr = sn_linked_list_remove_current_node(global_linked_list_ack_info_ptr);

            /* Free memory of stored Acknowledgement info */
            if(removed_ack_info_ptr->token_ptr)
            {
            	sn_coap_protocol_free(removed_ack_info_ptr->token_ptr);
            }
            sn_coap_protocol_free(removed_ack_info_ptr->addr_ptr);
            sn_coap_protocol_free(removed_ack_info_ptr);

            /* Remove current node moved list automatically to next node. That is why we can fetch it now by calling get current node. */
            removed_ack_info_ptr = sn_linked_list_get_current_node(global_linked_list_ack_info_ptr);
        }
        else
        {
            /* Get next stored message to be searched */
            removed_ack_info_ptr = sn_linked_list_get_next_node(global_linked_list_ack_info_ptr);
        }
    }
}

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT /* If Message duplication detection is not used at all, this part of code will not be compiled */

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_duplication_info_store(sn_nsdl_addr_s *addr_ptr, uint16_t msg_id)
 *
 * \brief Stores Duplication info to Linked list
 *
 * \param msg_id is Message ID to be stored
 * \param *addr_ptr is pointer to Address information to be stored
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_duplication_info_store(sn_nsdl_addr_s *addr_ptr,
                                                                uint16_t msg_id)
{
    coap_duplication_info_s *stored_duplication_info_ptr = NULL;

    /* * * * Allocating memory for stored Duplication info * * * */

    /* Allocate memory for stored Duplication info's structure */
    stored_duplication_info_ptr = sn_coap_protocol_malloc(sizeof(coap_duplication_info_s));

    if (stored_duplication_info_ptr == NULL)
    {
        return;
    }

    /* Allocate memory for stored Duplication info's address */
    stored_duplication_info_ptr->addr_ptr = sn_coap_protocol_malloc(addr_ptr->addr_len);

    if (stored_duplication_info_ptr->addr_ptr == NULL)
    {
        sn_coap_protocol_free(stored_duplication_info_ptr);

        return;
    }

    /* * * * Filling fields of stored Duplication info * * * */

    stored_duplication_info_ptr->timestamp = global_system_time;
    stored_duplication_info_ptr->addr_len = addr_ptr->addr_len;
    memcpy(stored_duplication_info_ptr->addr_ptr, addr_ptr->addr_ptr, addr_ptr->addr_len);
    stored_duplication_info_ptr->port = addr_ptr->port;
    stored_duplication_info_ptr->msg_id = msg_id;

    /* * * * Storing Duplication info to Linked list * * * */

    sn_linked_list_add_node(global_linked_list_duplication_msgs_ptr, stored_duplication_info_ptr);
}

/**************************************************************************//**
 * \fn static int8_t sn_coap_protocol_linked_list_duplication_info_search(sn_nsdl_addr_s *addr_ptr, uint16_t msg_id)
 *
 * \brief Searches stored message from Linked list (Address and Message ID as key)
 *
 * \param *addr_ptr is pointer to Address key to be searched
 * \param msg_id is Message ID key to be searched
 *
 * \return Return value is 0 when message found and -1 if not found
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static int8_t sn_coap_protocol_linked_list_duplication_info_search(sn_nsdl_addr_s *addr_ptr,
                                                                   uint16_t msg_id)
{
    coap_duplication_info_s *stored_duplication_info_ptr   = sn_linked_list_get_last_node(global_linked_list_duplication_msgs_ptr);
    uint16_t                 stored_duplication_msgs_count = sn_linked_list_count_nodes(global_linked_list_duplication_msgs_ptr);
    uint8_t                  i                             = 0;

    /* Loop all nodes in Linked list for searching Message ID */
    for (i = 0; i < stored_duplication_msgs_count; i++)
    {
        /* If message's Message ID is same than is searched */
        if (stored_duplication_info_ptr->msg_id == msg_id)
        {
            int8_t mem_cmp_result = memcmp(addr_ptr->addr_ptr, stored_duplication_info_ptr->addr_ptr, addr_ptr->addr_len);

            /* If message's Source address is same than is searched */
            if (mem_cmp_result == 0)
            {
                /* If message's Source address port is same than is searched */
                if (stored_duplication_info_ptr->port == addr_ptr->port)
                {
                    /* * * Correct Duplication info found * * * */
                    return 0;
                }
            }
        }
        /* Get next stored Duplication info to be searched */
        stored_duplication_info_ptr = sn_linked_list_get_previous_node(global_linked_list_duplication_msgs_ptr);
    }

    return -1;
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_duplication_info_remove(uint8_t *addr_ptr, uint16_t port, uint16_t msg_id)
 *
 * \brief Removes stored Duplication info from Linked list
 *
 * \param *addr_ptr is pointer to Address key to be removed
 *
 * \param port is Port key to be removed
 *
 * \param msg_id is Message ID key to be removed
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_duplication_info_remove(uint8_t *addr_ptr, uint16_t port, uint16_t msg_id)
{
    coap_duplication_info_s *removed_duplication_info_ptr  = sn_linked_list_get_last_node(global_linked_list_duplication_msgs_ptr);
    uint16_t                 stored_duplication_msgs_count = sn_linked_list_count_nodes(global_linked_list_duplication_msgs_ptr);
    uint8_t                  i                             = 0;

    /* Loop all stored duplication messages in Linked list */
    for (i = 0; i < stored_duplication_msgs_count; i++)
    {
        int8_t mem_cmp_result = memcmp(addr_ptr, removed_duplication_info_ptr->addr_ptr, removed_duplication_info_ptr->addr_len);

        /* If message's Address is same than is searched */
        if (mem_cmp_result == 0)
        {
            /* If message's Address prt is same than is searched */
            if (removed_duplication_info_ptr->port == port)
            {
                /* If Message ID is same than is searched */
                if (removed_duplication_info_ptr->msg_id == msg_id)
                {
                    /* * * * Correct Duplication info found, remove it from Linked list * * * */
                    removed_duplication_info_ptr = sn_linked_list_remove_current_node(global_linked_list_duplication_msgs_ptr);

                    /* Free memory of stored Duplication info */
                    sn_coap_protocol_free(removed_duplication_info_ptr->addr_ptr);
                    sn_coap_protocol_free(removed_duplication_info_ptr);

                    return;
                }
            }
        }

        /* Get next stored message to be searched */
        removed_duplication_info_ptr = sn_linked_list_get_previous_node(global_linked_list_duplication_msgs_ptr);
    }
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_duplication_info_remove_old_ones(void)
 *
 * \brief Removes old stored Duplication detection infos from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_duplication_info_remove_old_ones(void)
{
    coap_duplication_info_s *removed_duplication_info_ptr  = sn_linked_list_get_first_node(global_linked_list_duplication_msgs_ptr);

    /* Loop all stored duplication messages in Linked list */
    while(removed_duplication_info_ptr)
    {
        if ((global_system_time - removed_duplication_info_ptr->timestamp)  > SN_COAP_DUPLICATION_MAX_TIME_MSGS_STORED)
        {
            /* * * * Old Duplication info found, remove it from Linked list * * * */
            removed_duplication_info_ptr = sn_linked_list_remove_current_node(global_linked_list_duplication_msgs_ptr);

            /* Free memory of stored Duplication info */
            sn_coap_protocol_free(removed_duplication_info_ptr->addr_ptr);
            sn_coap_protocol_free(removed_duplication_info_ptr);

            removed_duplication_info_ptr = sn_linked_list_get_current_node(global_linked_list_duplication_msgs_ptr);
        }
        else
        {
            /* Get next stored message to be searched */
            removed_duplication_info_ptr = sn_linked_list_get_next_node(global_linked_list_duplication_msgs_ptr);
        }
    }
}

#endif /* SN_COAP_DUPLICATION_MAX_MSGS_COUNT */

#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE
/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_blockwise_msg_remove_current()
 *
 * \brief Removes current stored blockwise message from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_blockwise_msg_remove_current()
{
    coap_blockwise_msg_s *removed_msg_ptr = sn_linked_list_remove_current_node(global_linked_list_blockwise_sent_msgs_ptr);

    if (removed_msg_ptr != NULL)
    {
        if(removed_msg_ptr->coap_msg_ptr->payload_ptr)
        	sn_coap_protocol_free(removed_msg_ptr->coap_msg_ptr->payload_ptr);

        sn_coap_parser_release_allocated_coap_msg_mem(removed_msg_ptr->coap_msg_ptr);

        sn_coap_protocol_free(removed_msg_ptr);
    }
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_blockwise_payload_store(sn_nsdl_addr_s *addr_ptr, uint16_t stored_payload_len, uint8_t *stored_payload_ptr)
 *
 * \brief Stores blockwise payload to Linked list
 *
 * \param *addr_ptr is pointer to Address information to be stored
 * \param stored_payload_len is length of stored Payload
 * \param *stored_payload_ptr is pointer to stored Payload
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_blockwise_payload_store(sn_nsdl_addr_s *addr_ptr,//TODO: addr + header parametreiksi, blokin offset talteen.
                                                                 uint16_t stored_payload_len,
                                                                 uint8_t *stored_payload_ptr)
{
	if(!addr_ptr || !stored_payload_len || !stored_payload_ptr)
		return;

    coap_blockwise_payload_s *stored_blockwise_payload_ptr = NULL;

    /* * * * Allocating memory for stored Payload  * * * */

    /* Allocate memory for stored Payload's structure */
    stored_blockwise_payload_ptr = sn_coap_protocol_malloc(sizeof(coap_blockwise_payload_s));

    if (stored_blockwise_payload_ptr == NULL)
    {
        return;
    }

    /* Allocate memory for stored Payload's data */
    stored_blockwise_payload_ptr->payload_ptr = sn_coap_protocol_malloc(stored_payload_len);

    if (stored_blockwise_payload_ptr->payload_ptr == NULL)
    {
        sn_coap_protocol_free(stored_blockwise_payload_ptr);

        return;
    }

    /* Allocate memory for stored Payload's address */
    stored_blockwise_payload_ptr->addr_ptr = sn_coap_protocol_malloc(addr_ptr->addr_len);

    if (stored_blockwise_payload_ptr->addr_ptr == NULL)
    {
        sn_coap_protocol_free(stored_blockwise_payload_ptr);
        sn_coap_protocol_free(stored_blockwise_payload_ptr->payload_ptr);

        return;
    }

    /* * * * Filling fields of stored Payload  * * * */

    stored_blockwise_payload_ptr->timestamp = global_system_time;

    memcpy(stored_blockwise_payload_ptr->addr_ptr, addr_ptr->addr_ptr, addr_ptr->addr_len);
    stored_blockwise_payload_ptr->port = addr_ptr->port;
    memcpy(stored_blockwise_payload_ptr->payload_ptr, stored_payload_ptr, stored_payload_len);
    stored_blockwise_payload_ptr->payload_len = stored_payload_len;

    /* * * * Storing Payload to Linked list  * * * */

    sn_linked_list_add_node(global_linked_list_blockwise_received_payloads_ptr, stored_blockwise_payload_ptr);//TODO: hukkAS
}

/**************************************************************************//**
 * \fn static uint8_t *sn_coap_protocol_linked_list_blockwise_payload_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t *payload_length)
 *
 * \brief Searches stored blockwise payload from Linked list (Address as key)
 *
 * \param *addr_ptr is pointer to Address key to be searched
 * \param *payload_length is pointer to returned Payload length
 *
 * \return Return value is pointer to found stored blockwise payload in Linked
 *         list or NULL if payload not found
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static uint8_t *sn_coap_protocol_linked_list_blockwise_payload_search(sn_nsdl_addr_s *src_addr_ptr, uint16_t *payload_length)
{
    coap_blockwise_payload_s *stored_payload_info_ptr       = sn_linked_list_get_last_node(global_linked_list_blockwise_received_payloads_ptr);
    uint16_t                  stored_blockwise_payloads_count = sn_linked_list_count_nodes(global_linked_list_blockwise_received_payloads_ptr);
    uint8_t                   i                               = 0;

    /* Loop all stored blockwise payloads in Linked list */
    for (i = 0; i < stored_blockwise_payloads_count; i++)
    {
        int8_t mem_cmp_result = memcmp(src_addr_ptr->addr_ptr, stored_payload_info_ptr->addr_ptr, src_addr_ptr->addr_len);

        /* If payload's Source address is same than is searched */
        if (mem_cmp_result == 0)
        {
            /* If payload's Source address port is same than is searched */
            if (stored_payload_info_ptr->port == src_addr_ptr->port)
            {
                /* * * Correct Payload found * * * */
                *payload_length = stored_payload_info_ptr->payload_len;

                return stored_payload_info_ptr->payload_ptr;
            }
        }

        /* Get next stored payload to be searched */
        stored_payload_info_ptr = sn_linked_list_get_previous_node(global_linked_list_blockwise_received_payloads_ptr);
    }

    return NULL;
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_blockwise_payload_remove_oldest()
 *
 * \brief Removes current stored blockwise paylod from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_blockwise_payload_remove_oldest()
{
    coap_blockwise_payload_s *removed_payload_ptr = NULL;

    /* Set Linked list to point oldest node */
    sn_linked_list_get_last_node(global_linked_list_blockwise_received_payloads_ptr);

    /* Remove oldest node in Linked list*/
    removed_payload_ptr = sn_linked_list_remove_current_node(global_linked_list_blockwise_received_payloads_ptr);

    /* Free memory of stored payload */
    if (removed_payload_ptr != NULL)
    {
        if (removed_payload_ptr->addr_ptr != NULL)
        {
            sn_coap_protocol_free(removed_payload_ptr->addr_ptr);
        }

        if (removed_payload_ptr->payload_ptr != NULL)
        {
            sn_coap_protocol_free(removed_payload_ptr->payload_ptr);
        }

        sn_coap_protocol_free(removed_payload_ptr);
    }
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_blockwise_payload_remove_current()
 *
 * \brief Removes current stored blockwise paylod from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_blockwise_payload_remove_current()
{
    coap_blockwise_payload_s *removed_payload_ptr = NULL;

    /* Remove oldest node in Linked list*/
    removed_payload_ptr = sn_linked_list_remove_current_node(global_linked_list_blockwise_received_payloads_ptr);

    /* Free memory of stored payload */
    if (removed_payload_ptr != NULL)
    {
        if (removed_payload_ptr->addr_ptr != NULL)
        {
            sn_coap_protocol_free(removed_payload_ptr->addr_ptr);
        }

        if (removed_payload_ptr->payload_ptr != NULL)
        {
            sn_coap_protocol_free(removed_payload_ptr->payload_ptr);
        }

        sn_coap_protocol_free(removed_payload_ptr);
    }
}

/**************************************************************************//**
 * \fn static uint16_t sn_coap_protocol_linked_list_blockwise_payloads_get_len(sn_nsdl_addr_s *src_addr_ptr)
 *
 * \brief Counts length of Payloads in Linked list (Address as key)
 *
 * \param *addr_ptr is pointer to Address key
 *
 * \return Return value is length of Payloads as bytes
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static uint16_t sn_coap_protocol_linked_list_blockwise_payloads_get_len(sn_nsdl_addr_s *src_addr_ptr)
{
    coap_blockwise_payload_s *searched_payload_info_ptr       = sn_linked_list_get_last_node(global_linked_list_blockwise_received_payloads_ptr);
    uint16_t                  stored_blockwise_payloads_count = sn_linked_list_count_nodes(global_linked_list_blockwise_received_payloads_ptr);
    uint8_t                   i                               = 0;
    uint16_t                  ret_whole_payload_len           = 0;

    /* Loop all stored blockwise payloads in Linked list */
    for (i = 0; i < stored_blockwise_payloads_count; i++)
    {
        int8_t mem_cmp_result = memcmp(src_addr_ptr->addr_ptr, searched_payload_info_ptr->addr_ptr, src_addr_ptr->addr_len);

        /* If payload's Source address is same than is searched */
        if (mem_cmp_result == 0)
        {
            /* If payload's Source address port is same than is searched */
            if (searched_payload_info_ptr->port == src_addr_ptr->port)
            {
                /* * * Correct Payload found * * * */
                ret_whole_payload_len += searched_payload_info_ptr->payload_len;
            }
        }

        /* Get next stored payload to be searched */
        searched_payload_info_ptr = sn_linked_list_get_previous_node(global_linked_list_blockwise_received_payloads_ptr);
    }

    return ret_whole_payload_len;
}

/**************************************************************************//**
 * \fn static void sn_coap_protocol_linked_list_blockwise_remove_old_data(void)
 *
 * \brief Removes old stored Blockwise messages and payloads from Linked list
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_linked_list_blockwise_remove_old_data(void)
{
    coap_blockwise_msg_s     *removed_blocwise_msg_ptr        = sn_linked_list_get_first_node(global_linked_list_blockwise_sent_msgs_ptr);
    coap_blockwise_payload_s *removed_blocwise_payload_ptr    = sn_linked_list_get_first_node(global_linked_list_blockwise_received_payloads_ptr);

    /* Loop all stored Blockwise messages in Linked list */
    while(removed_blocwise_msg_ptr)
    {
        if ((global_system_time - removed_blocwise_msg_ptr->timestamp)  > SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED)
        {
            /* * * * Old Blockise message found, remove it from Linked list * * * */
            sn_coap_protocol_linked_list_blockwise_msg_remove_current();
            removed_blocwise_msg_ptr = sn_linked_list_get_current_node(global_linked_list_blockwise_sent_msgs_ptr);
        }
        else
        {
            /* Get next stored message to be searched */
            removed_blocwise_msg_ptr = sn_linked_list_get_next_node(global_linked_list_blockwise_sent_msgs_ptr);
        }
    }

    /* Loop all stored Blockwise payloads in Linked list */
    while(removed_blocwise_payload_ptr)
    {
        if ((global_system_time - removed_blocwise_payload_ptr->timestamp)  > SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED)
        {
            /* * * * Old Blockise payload found, remove it from Linked list * * * */
            sn_coap_protocol_linked_list_blockwise_payload_remove_current();
            removed_blocwise_payload_ptr = sn_linked_list_get_current_node(global_linked_list_blockwise_received_payloads_ptr);

        }
        else
        {
        	/* Get next stored payload to be searched */
        	removed_blocwise_payload_ptr = sn_linked_list_get_next_node(global_linked_list_blockwise_received_payloads_ptr);
        }
    }
}

#endif /* SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE */

#if SN_COAP_RESENDING_MAX_COUNT
/**************************************************************************//**
 * \fn sn_nsdl_transmit_s *sn_coap_protocol_build_msg(void *src_msg_ptr)
 *
 * \brief Builds message (sn_nsdl_transmit_s) from given data
 *
 * \param *src_msg_ptr is pointer to source of built message
 *
 * \return Return value is pointer to built message
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
sn_nsdl_transmit_s *sn_coap_protocol_build_msg(void *src_msg_ptr)
{
    /* Allocate memory for structures behind sending messages list pointers */

    sn_nsdl_transmit_s *returned_msg_ptr = sn_coap_protocol_malloc(sizeof(sn_nsdl_transmit_s));

    if (returned_msg_ptr == NULL)
        return NULL;

    returned_msg_ptr->dst_addr_ptr = sn_coap_protocol_malloc(sizeof(sn_nsdl_addr_s));

    if (returned_msg_ptr->dst_addr_ptr == NULL)
    {
        sn_coap_builder_release_allocated_send_msg_mem(returned_msg_ptr);
        return NULL;
    }

    returned_msg_ptr->packet_ptr = sn_coap_protocol_malloc(((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->packet_len);

    if (returned_msg_ptr->packet_ptr == NULL)
    {
        sn_coap_builder_release_allocated_send_msg_mem(returned_msg_ptr);
        return NULL;
    }

    returned_msg_ptr->dst_addr_ptr->addr_ptr = sn_coap_protocol_malloc(((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_len);

    if (returned_msg_ptr->dst_addr_ptr->addr_ptr == NULL)
    {
        sn_coap_builder_release_allocated_send_msg_mem(returned_msg_ptr);
        return NULL;
    }

    /* Filling of sn_nsdl_transmit_s */
    returned_msg_ptr->protocol = ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->protocol;
    returned_msg_ptr->packet_len = ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->packet_len;
    memcpy(returned_msg_ptr->packet_ptr, ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->packet_ptr, ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->packet_len);

    /* Filling of sn_nsdl_addr_s */
    returned_msg_ptr->dst_addr_ptr->type = ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->type;
    returned_msg_ptr->dst_addr_ptr->addr_len = ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_len;
    memcpy(returned_msg_ptr->dst_addr_ptr->addr_ptr, ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_ptr, ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_len);
    returned_msg_ptr->dst_addr_ptr->port = ((coap_send_msg_s*)src_msg_ptr)->send_msg_ptr->dst_addr_ptr->port;

    return returned_msg_ptr;
}
#endif /* SN_COAP_RESENDING_MAX_COUNT */


#if SN_COAP_RESENDING_MAX_COUNT || SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message resending is not used at all, this part of code will not be compiled */
/***************************************************************************//**
 * \fn int8_t sn_coap_protocol_allocate_mem_for_msg(sn_nsdl_addr_s *dst_addr_ptr, uint16_t packet_data_len, void *msg_ptr)
 *
 * \brief Allocates memory for given message (send or blockwise message)
 *
 * \param *dst_addr_ptr is pointer to destination address where message will be sent
 * \param packet_data_len is length of allocated Packet data
 * \param *msg_ptr is pointer to allocated message
 *
 * \return Return value
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
int8_t sn_coap_protocol_allocate_mem_for_msg(sn_nsdl_addr_s *dst_addr_ptr, uint16_t packet_data_len, void *msg_ptr)
{
    ((coap_send_msg_s*)msg_ptr)->send_msg_ptr = sn_coap_protocol_malloc(sizeof(sn_nsdl_transmit_s));

    if (((coap_send_msg_s*)msg_ptr)->send_msg_ptr == NULL)
    {
        sn_coap_protocol_release_allocated_send_msg_mem(msg_ptr);
        return -1;
    }

    ((coap_send_msg_s*)msg_ptr)->send_msg_ptr->dst_addr_ptr = sn_coap_protocol_malloc(sizeof(sn_nsdl_addr_s));

    if (((coap_send_msg_s*)msg_ptr)->send_msg_ptr->dst_addr_ptr == NULL)
    {
        sn_coap_protocol_release_allocated_send_msg_mem(msg_ptr);
        return -1;
    }

    ((coap_send_msg_s*)msg_ptr)->send_msg_ptr->packet_ptr = sn_coap_protocol_malloc(packet_data_len);

    if (((coap_send_msg_s*)msg_ptr)->send_msg_ptr->packet_ptr == NULL)
    {
        sn_coap_protocol_release_allocated_send_msg_mem(msg_ptr);
        return -1;
    }

    ((coap_send_msg_s*)msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_ptr = sn_coap_protocol_malloc(dst_addr_ptr->addr_len);

    if (((coap_send_msg_s*)msg_ptr)->send_msg_ptr->dst_addr_ptr->addr_ptr == NULL)
    {
        sn_coap_protocol_release_allocated_send_msg_mem(msg_ptr);
        return - 1;
    }

    return 0;
}


/**************************************************************************//**
 * \fn static void sn_coap_protocol_release_allocated_send_msg_mem(coap_send_msg_s *freed_send_msg_ptr)
 *
 * \brief Releases memory of given Sending message (coap_send_msg_s)
 *
 * \param *freed_send_msg_ptr is pointer to released Sending message
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static void sn_coap_protocol_release_allocated_send_msg_mem(coap_send_msg_s *freed_send_msg_ptr)
{
    if (freed_send_msg_ptr != NULL)
    {
        sn_coap_builder_release_allocated_send_msg_mem(freed_send_msg_ptr->send_msg_ptr);
        sn_coap_protocol_free(freed_send_msg_ptr);
    }
}

#endif
#if SN_COAP_BLOCKWISE_MAX_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
/**************************************************************************//**
 * \fn static int8_t sn_coap_handle_blockwise_message(void)
 *
 * \brief Handles all received blockwise messages
 *
 * \param *src_addr_ptr pointer to source address information struct
 * \param *received_coap_msg_ptr pointer to parsed CoAP message structure
 *****************************************************************************/
SN_MEM_ATTR_COAP_PROTOCOL_FUNC
static sn_coap_hdr_s *sn_coap_handle_blockwise_message(sn_nsdl_addr_s *src_addr_ptr, sn_coap_hdr_s *received_coap_msg_ptr)
{
    sn_coap_hdr_s *src_coap_blockwise_ack_msg_ptr = NULL;
    uint16_t dst_packed_data_needed_mem = 0;
    uint8_t *dst_ack_packet_data_ptr = NULL;
    sn_nsdl_transmit_s *previous_message_ptr = NULL;
    coap_version_e   coap_version = COAP_VERSION_UNKNOWN;
    uint8_t block_temp = 0;

    uint16_t original_payload_len = 0;
    uint8_t *original_payload_ptr = NULL;

	/* Block1 Option in a request (e.g., PUT or POST) */
	// Blocked request sending
	if(received_coap_msg_ptr->options_list_ptr->block1_ptr)
    {
		if(received_coap_msg_ptr->msg_code > COAP_MSG_CODE_REQUEST_DELETE)
		{
			if(*(received_coap_msg_ptr->options_list_ptr->block1_ptr + (received_coap_msg_ptr->options_list_ptr->block1_len - 1)) & 0x08)
			{
				coap_blockwise_msg_s *stored_blockwise_msg_temp_ptr = sn_linked_list_get_last_node(global_linked_list_blockwise_sent_msgs_ptr);
				if(stored_blockwise_msg_temp_ptr)
				{
					/* Build response message */

					uint16_t block_size = 1;
					uint32_t block_number = 0;

					/* Get block option parameters from received message */
					if(received_coap_msg_ptr->options_list_ptr->block1_len == 3)
					{
						block_number = *(received_coap_msg_ptr->options_list_ptr->block1_ptr) << 12;
						block_number |= *(received_coap_msg_ptr->options_list_ptr->block1_ptr + 1) << 4;
						block_number |= (*(received_coap_msg_ptr->options_list_ptr->block1_ptr + 2)) >> 4;
					}

					else if(received_coap_msg_ptr->options_list_ptr->block1_len == 2)
					{
						block_number = *(received_coap_msg_ptr->options_list_ptr->block1_ptr) << 4;
						block_number |= (*(received_coap_msg_ptr->options_list_ptr->block1_ptr + 1)) >> 4;
					}
					else if(received_coap_msg_ptr->options_list_ptr->block1_len == 1)
					{
						block_number = (*received_coap_msg_ptr->options_list_ptr->block1_ptr) >> 4;
					}


					block_temp = *(received_coap_msg_ptr->options_list_ptr->block1_ptr + (received_coap_msg_ptr->options_list_ptr->block1_len - 1)) & 0x07;
					block_size = block_size << (block_temp + 4);


					/* Build next block message */
					src_coap_blockwise_ack_msg_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr;

					if(src_coap_blockwise_ack_msg_ptr->options_list_ptr)
					{
						if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr)
						{
							sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr);
							src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr = 0;

						}
						if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr)
						{
							sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr);
							src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr = 0;
						}
					}
					else
					{
						src_coap_blockwise_ack_msg_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));
						if(!src_coap_blockwise_ack_msg_ptr->options_list_ptr)
						{
							return 0;
						}
						memset(src_coap_blockwise_ack_msg_ptr->options_list_ptr, 0, (sizeof(sn_coap_options_list_s)));
					}

					block_number++;

					if(block_number <= 0x0f)
						src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len = 1;
					else if(block_number <= 0x0fff)
						src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len = 2;
					else if(block_number <= 0x0fffff)
						src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len = 3;

					src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr = sn_coap_protocol_malloc(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len);

					if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr == 0)
						return 0;

					*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len - 1)) = block_temp;
					*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr |= block_number << 4;


					if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len == 3)
					{
						*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + 2) = block_number << 4;
						*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + 1) |= block_number >> 4;
						*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr |= block_number >> 12;
					}
					else if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len == 2)
					{
						*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + 1) |= block_number << 4;
						*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr |= block_number >> 4;
					}
					else
						*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr = block_number << 4;

					original_payload_len = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len;
					original_payload_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr;

					if((block_size * (block_number+1)) > stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len)
					{
						src_coap_blockwise_ack_msg_ptr->payload_len = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len - (block_size * (block_number));
						src_coap_blockwise_ack_msg_ptr->payload_ptr = src_coap_blockwise_ack_msg_ptr->payload_ptr + (block_size * block_number);
					}

					/* Not last block */
					else
					{
						/* set more - bit */
						*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len-1)) |= 0x08;
						src_coap_blockwise_ack_msg_ptr->payload_len = block_size;
						src_coap_blockwise_ack_msg_ptr->payload_ptr = src_coap_blockwise_ack_msg_ptr->payload_ptr + (block_size * block_number);
					}

					/* Build and send block message */
	                dst_packed_data_needed_mem = sn_coap_builder_calc_needed_packet_data_size(src_coap_blockwise_ack_msg_ptr);

	                dst_ack_packet_data_ptr = sn_coap_protocol_malloc(dst_packed_data_needed_mem);
	                if(!dst_ack_packet_data_ptr)
	                {
	                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr);
	                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
	                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
	                    return NULL;
	                }
	                src_coap_blockwise_ack_msg_ptr->msg_id = global_message_id++;

	                sn_coap_builder(dst_ack_packet_data_ptr, src_coap_blockwise_ack_msg_ptr);

					sn_coap_tx_callback(SN_NSDL_PROTOCOL_COAP, dst_ack_packet_data_ptr, dst_packed_data_needed_mem, src_addr_ptr);

					sn_coap_protocol_free(dst_ack_packet_data_ptr);

					stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len = original_payload_len;
					stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr = original_payload_ptr;

					received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_ACK;
				}
			}
			else
			{
				sn_coap_protocol_linked_list_blockwise_msg_remove_current();
				received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_ACK;
			}
		}

		// Blocked request receiving
		else
		{
			if(received_coap_msg_ptr->payload_len > sn_coap_block_data_size)
				received_coap_msg_ptr->payload_len = sn_coap_block_data_size;

			sn_coap_protocol_linked_list_blockwise_payload_store(src_addr_ptr, received_coap_msg_ptr->payload_len, received_coap_msg_ptr->payload_ptr);
			/* If not last block (more value is set) */
            /* Block option length can be 1-3 bytes. First 4-20 bits are for block number. Last 4 bits are ALWAYS more bit + block size. */
            if(*(received_coap_msg_ptr->options_list_ptr->block1_ptr + (received_coap_msg_ptr->options_list_ptr->block1_len - 1)) & 0x08)
            {
            	//send ack
                src_coap_blockwise_ack_msg_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_hdr_s));

                if (src_coap_blockwise_ack_msg_ptr == NULL)
                {
                    return NULL;
                }

                memset(src_coap_blockwise_ack_msg_ptr, 0, sizeof(sn_coap_hdr_s));

                src_coap_blockwise_ack_msg_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));

                if (src_coap_blockwise_ack_msg_ptr->options_list_ptr == NULL)
                {
                    sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);

                    return NULL;
                }

                memset(src_coap_blockwise_ack_msg_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

               if(received_coap_msg_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
                	src_coap_blockwise_ack_msg_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
               else if(received_coap_msg_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST)
                	src_coap_blockwise_ack_msg_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
               else if(received_coap_msg_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
                	src_coap_blockwise_ack_msg_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
               else if(received_coap_msg_ptr->msg_code == COAP_MSG_CODE_REQUEST_DELETE)
                	src_coap_blockwise_ack_msg_ptr->msg_code = COAP_MSG_CODE_RESPONSE_DELETED;

                src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len = received_coap_msg_ptr->options_list_ptr->block1_len;
                src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr = sn_coap_protocol_malloc(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len);
                if(!src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr)
                {
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
                    return NULL;
                }

                src_coap_blockwise_ack_msg_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

                memcpy(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr, received_coap_msg_ptr->options_list_ptr->block1_ptr, received_coap_msg_ptr->options_list_ptr->block1_len);

                /* Check block size */
                block_temp = (*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len - 1)) & 0x07);
                if(block_temp > sn_coap_convert_block_size(sn_coap_block_data_size))
                {
                	*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len - 1)) &= 0xF8;
                	*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_len - 1)) |= sn_coap_convert_block_size(sn_coap_block_data_size);
                }

                src_coap_blockwise_ack_msg_ptr->msg_id = received_coap_msg_ptr->msg_id;

                dst_packed_data_needed_mem = sn_coap_builder_calc_needed_packet_data_size(src_coap_blockwise_ack_msg_ptr);

                dst_ack_packet_data_ptr = sn_coap_protocol_malloc(dst_packed_data_needed_mem);
                if(!dst_ack_packet_data_ptr)
                {
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
                    return NULL;
                }

                sn_coap_builder(dst_ack_packet_data_ptr, src_coap_blockwise_ack_msg_ptr);

                sn_coap_tx_callback(SN_NSDL_PROTOCOL_COAP, dst_ack_packet_data_ptr, dst_packed_data_needed_mem, src_addr_ptr);

                sn_coap_parser_release_allocated_coap_msg_mem(src_coap_blockwise_ack_msg_ptr);
                sn_coap_protocol_free(dst_ack_packet_data_ptr);

                received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING;

            }
            else
            {
                /* * * This is the last block when whole Blockwise payload from received * * */
                /* * * blockwise messages is gathered and returned to User               * * */

                /* Store last Blockwise payload to Linked list */
                uint16_t payload_len            = 0;
                uint8_t *payload_ptr            = sn_coap_protocol_linked_list_blockwise_payload_search(src_addr_ptr, &payload_len);
                uint16_t whole_payload_len      = sn_coap_protocol_linked_list_blockwise_payloads_get_len(src_addr_ptr);
                uint8_t *temp_whole_payload_ptr = NULL;

                temp_whole_payload_ptr = sn_coap_protocol_malloc(whole_payload_len);
                if(!temp_whole_payload_ptr)
                	return 0;

                received_coap_msg_ptr->payload_ptr = temp_whole_payload_ptr;
                received_coap_msg_ptr->payload_len = whole_payload_len;

                /* Copy stored Blockwise payloads to returned whole Blockwise payload pointer */
                while (payload_ptr != NULL)
                {
                    memcpy(temp_whole_payload_ptr, payload_ptr, payload_len);

                    temp_whole_payload_ptr += payload_len;

                    sn_coap_protocol_linked_list_blockwise_payload_remove_oldest();
                    payload_ptr = sn_coap_protocol_linked_list_blockwise_payload_search(src_addr_ptr, &payload_len);
                }
            	received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED;
            }
		}
    }


	/* Block2 Option in a response (e.g., a 2.05 response for GET) */
	/* Message ID must be same than in received message */
	else
    {
		//This is response to request we made
		if(received_coap_msg_ptr->msg_code > COAP_MSG_CODE_REQUEST_DELETE)
		{
			uint32_t block_number = 0;

            /* Store blockwise payload to Linked list */
			//todo: add block number to stored values - just to make sure all packets are in order
            sn_coap_protocol_linked_list_blockwise_payload_store(src_addr_ptr, received_coap_msg_ptr->payload_len, received_coap_msg_ptr->payload_ptr);

			/* If not last block (more value is set) */
            if(*(received_coap_msg_ptr->options_list_ptr->block2_ptr + (received_coap_msg_ptr->options_list_ptr->block2_len - 1)) & 0x08)
            {
            	//build and send ack
            	received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING;

            	previous_message_ptr = sn_coap_protocol_linked_list_send_msg_search(src_addr_ptr, received_coap_msg_ptr->msg_id);
            	if(!previous_message_ptr)
            		return 0;

            	src_coap_blockwise_ack_msg_ptr = sn_coap_parser(previous_message_ptr->packet_len, previous_message_ptr->packet_ptr, &coap_version);

            	if(src_coap_blockwise_ack_msg_ptr->payload_ptr)
            	{
            		src_coap_blockwise_ack_msg_ptr->payload_ptr = 0;
            		src_coap_blockwise_ack_msg_ptr->payload_len = 0;
            	}

				/* * * Then build CoAP Acknowledgement message * * */
            	if(!src_coap_blockwise_ack_msg_ptr->options_list_ptr)
            	{
            		src_coap_blockwise_ack_msg_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));
            		if(!src_coap_blockwise_ack_msg_ptr->options_list_ptr)
            		{
            			sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
            			return 0;
            		}
            		memset(src_coap_blockwise_ack_msg_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
            	}

            	src_coap_blockwise_ack_msg_ptr->msg_id = global_message_id++;

            	if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr)
            		sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr);

            	/* Update block option */
            	block_temp = *(received_coap_msg_ptr->options_list_ptr->block2_ptr + ( received_coap_msg_ptr->options_list_ptr->block2_len - 1)) & 0x07;

				if(received_coap_msg_ptr->options_list_ptr->block2_len == 3)
				{
					block_number = *(received_coap_msg_ptr->options_list_ptr->block2_ptr) << 12;
					block_number |= *(received_coap_msg_ptr->options_list_ptr->block2_ptr + 1) << 4;
					block_number |= (*(received_coap_msg_ptr->options_list_ptr->block2_ptr + 2)) >> 4;
				}

				else if(received_coap_msg_ptr->options_list_ptr->block2_len == 2)
				{
					block_number = *(received_coap_msg_ptr->options_list_ptr->block2_ptr) << 4;
					block_number |= (*(received_coap_msg_ptr->options_list_ptr->block2_ptr + 1)) >> 4;
				}
				else if(received_coap_msg_ptr->options_list_ptr->block2_len == 1)
				{
					block_number = (*received_coap_msg_ptr->options_list_ptr->block2_ptr) >> 4;
				}

				if(block_number == 0x0f)
					asm("nop");

				block_number ++;

				if(block_number <= 0x0f)
					src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len = 1;
				else if(block_number <= 0x0fff)
					src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len = 2;
				else if(block_number <= 0x0fffff)
					src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len = 3;

				src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr = sn_coap_protocol_malloc(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len);

				if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr == 0)
				{
					sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
					sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);

					return 0;
				}

				*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len - 1)) = block_temp;

				if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len == 3)
				{
					*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr + 2) = block_number << 4;
					*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr + 1) |= block_number >> 4;
					*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr |= block_number >> 12;
				}
				else if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len == 2)
				{
					*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr + 1) = block_number << 4;
					*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr |= block_number >> 4;
				}
				else
					*src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr = block_number << 4;

                /* Then get needed memory count for Packet data */
                dst_packed_data_needed_mem = sn_coap_builder_calc_needed_packet_data_size(src_coap_blockwise_ack_msg_ptr);

                /* Then allocate memory for Packet data */
                dst_ack_packet_data_ptr = sn_coap_protocol_malloc(dst_packed_data_needed_mem);
                memset(dst_ack_packet_data_ptr, 0, dst_packed_data_needed_mem);

                if (dst_ack_packet_data_ptr == NULL)
                {
                    sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
                    sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
                    sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr);

                    return NULL;
                }

                /* * * Then build Acknowledgement message to Packed data * * */
                if ((sn_coap_builder(dst_ack_packet_data_ptr, src_coap_blockwise_ack_msg_ptr)) < 0)
                {
                	sn_coap_protocol_free(dst_ack_packet_data_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
                	sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr);
                    return NULL;
                }

                /* * * Then release memory of CoAP Acknowledgement message * * */
                sn_coap_parser_release_allocated_coap_msg_mem(src_coap_blockwise_ack_msg_ptr);

                sn_coap_protocol_linked_list_send_msg_remove(src_addr_ptr, received_coap_msg_ptr->msg_id);

				sn_coap_tx_callback(SN_NSDL_PROTOCOL_COAP, dst_ack_packet_data_ptr,
									dst_packed_data_needed_mem, src_addr_ptr);

				sn_coap_protocol_linked_list_send_msg_store(src_addr_ptr,
															dst_packed_data_needed_mem,
															dst_ack_packet_data_ptr,
															global_system_time + (uint32_t)(RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR));

				sn_coap_protocol_free(dst_ack_packet_data_ptr);
            }

            //Last block received
            else
            {
                /* * * This is the last block when whole Blockwise payload from received * * */
                /* * * blockwise messages is gathered and returned to User               * * */

                /* Store last Blockwise payload to Linked list */
                uint16_t payload_len            = 0;
                uint8_t *payload_ptr            = sn_coap_protocol_linked_list_blockwise_payload_search(src_addr_ptr, &payload_len);
                uint16_t whole_payload_len      = sn_coap_protocol_linked_list_blockwise_payloads_get_len(src_addr_ptr);
                uint8_t *temp_whole_payload_ptr = NULL;

                temp_whole_payload_ptr = sn_coap_protocol_malloc(whole_payload_len);
                if(!temp_whole_payload_ptr)
                	return 0;

                received_coap_msg_ptr->payload_ptr = temp_whole_payload_ptr;
                received_coap_msg_ptr->payload_len = whole_payload_len;

                /* Copy stored Blockwise payloads to returned whole Blockwise payload pointer */
                while (payload_ptr != NULL)
                {
                    memcpy(temp_whole_payload_ptr, payload_ptr, payload_len);

                    temp_whole_payload_ptr += payload_len;

                    sn_coap_protocol_linked_list_blockwise_payload_remove_oldest();
                    payload_ptr = sn_coap_protocol_linked_list_blockwise_payload_search(src_addr_ptr, &payload_len);
                }
            	received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED;

            	sn_coap_protocol_linked_list_send_msg_remove(src_addr_ptr, received_coap_msg_ptr->msg_id);
            }

		}

		//Now we send data to request
		else
		{
			//Get message by using block number
			coap_blockwise_msg_s *stored_blockwise_msg_temp_ptr = sn_linked_list_get_last_node(global_linked_list_blockwise_sent_msgs_ptr);
			if(stored_blockwise_msg_temp_ptr)
			{
				uint16_t block_size = 1;
				uint32_t block_number = 0;

				/* Resolve block parameters */
				if(received_coap_msg_ptr->options_list_ptr->block2_len == 3)
				{
					block_number = *(received_coap_msg_ptr->options_list_ptr->block2_ptr) << 12;
					block_number |= *(received_coap_msg_ptr->options_list_ptr->block2_ptr + 1) << 4;
					block_number |= (*(received_coap_msg_ptr->options_list_ptr->block2_ptr + 2)) >> 4;
				}

				else if(received_coap_msg_ptr->options_list_ptr->block2_len == 2)
				{
					block_number = *(received_coap_msg_ptr->options_list_ptr->block2_ptr) << 4;
					block_number |= (*(received_coap_msg_ptr->options_list_ptr->block2_ptr + 1)) >> 4;
				}
				else if(received_coap_msg_ptr->options_list_ptr->block2_len == 1)
				{
					block_number = (*received_coap_msg_ptr->options_list_ptr->block2_ptr) >> 4;
				}

				block_temp = *(received_coap_msg_ptr->options_list_ptr->block2_ptr + (received_coap_msg_ptr->options_list_ptr->block2_len - 1)) & 0x07;
				block_size = block_size << (block_temp + 4);

				/* Build response message */
				src_coap_blockwise_ack_msg_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr;

				if(src_coap_blockwise_ack_msg_ptr->options_list_ptr)
				{
					if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr)
					{
						sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr);
						src_coap_blockwise_ack_msg_ptr->options_list_ptr->block1_ptr = 0;

					}
					if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr)
					{
						sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr);
						src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr = 0;
					}
				}
				else
				{
					src_coap_blockwise_ack_msg_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));
					if(!src_coap_blockwise_ack_msg_ptr->options_list_ptr)
					{
						return 0;
					}
					memset(src_coap_blockwise_ack_msg_ptr->options_list_ptr, 0, (sizeof(sn_coap_options_list_s)));
				}


				src_coap_blockwise_ack_msg_ptr->msg_id = received_coap_msg_ptr->msg_id;

				src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len = received_coap_msg_ptr->options_list_ptr->block2_len;
				src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr = sn_coap_protocol_malloc(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len);

				if(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr == NULL)
				{
					sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr->options_list_ptr);
					sn_coap_protocol_free(src_coap_blockwise_ack_msg_ptr);
					return NULL;
				}
				memcpy(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr, received_coap_msg_ptr->options_list_ptr->block2_ptr, src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len);

				/* * Payload part * */

				/* Check if last block */

				original_payload_len = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len;
				original_payload_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr;

				if((block_size * (block_number + 1)) > stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len)
				{
					src_coap_blockwise_ack_msg_ptr->payload_len = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len - (block_size * block_number);
					src_coap_blockwise_ack_msg_ptr->payload_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr + (block_size * block_number);
				}
				/* Not last block */
				else
				{
					/* set more - bit */
					*(src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_ptr + (src_coap_blockwise_ack_msg_ptr->options_list_ptr->block2_len-1)) |= 0x08;
					src_coap_blockwise_ack_msg_ptr->payload_len = block_size;
					src_coap_blockwise_ack_msg_ptr->payload_ptr = stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr + (block_size * block_number);
				}

				/* Build and send block message */
                dst_packed_data_needed_mem = sn_coap_builder_calc_needed_packet_data_size(src_coap_blockwise_ack_msg_ptr);

                dst_ack_packet_data_ptr = sn_coap_protocol_malloc(dst_packed_data_needed_mem);
                if(!dst_ack_packet_data_ptr)
                {
                    return NULL;
                }

                sn_coap_builder(dst_ack_packet_data_ptr, src_coap_blockwise_ack_msg_ptr);

				sn_coap_tx_callback(SN_NSDL_PROTOCOL_COAP, dst_ack_packet_data_ptr, dst_packed_data_needed_mem, src_addr_ptr);

				sn_coap_protocol_free(dst_ack_packet_data_ptr);

				stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len = original_payload_len;
				stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_ptr = original_payload_ptr;

                if((block_size * (block_number + 1)) > stored_blockwise_msg_temp_ptr->coap_msg_ptr->payload_len)
                	sn_coap_protocol_linked_list_blockwise_msg_remove_current();

				received_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_BLOCKWISE_ACK;
			}
		}
    }
	return received_coap_msg_ptr;
}

static uint8_t sn_coap_convert_block_size(uint16_t block_size)
{
	if(block_size == 16)
		return 0;
	else if(block_size == 32)
		return 1;
	else if(block_size == 64)
		return 2;
	else if(block_size == 128)
		return 3;
	else if(block_size == 256)
		return 4;
	else if(block_size == 512)
		return 5;
	else if(block_size == 1024)
		return 6;

	return -1;
}

static sn_coap_hdr_s *sn_coap_protocol_copy_header(sn_coap_hdr_s *source_header_ptr)
{
	sn_coap_hdr_s *destination_header_ptr;

	destination_header_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_hdr_s));
	if(!destination_header_ptr)
		return 0;
	memset(destination_header_ptr, 0, sizeof(sn_coap_hdr_s));

	destination_header_ptr->coap_status = source_header_ptr->coap_status;
	destination_header_ptr->msg_type = source_header_ptr->msg_type;
	destination_header_ptr->msg_code = source_header_ptr->msg_code;
	destination_header_ptr->msg_id = source_header_ptr->msg_id;

	if(source_header_ptr->uri_path_ptr)
	{
		destination_header_ptr->uri_path_len = source_header_ptr->uri_path_len;
		destination_header_ptr->uri_path_ptr = sn_coap_protocol_malloc(source_header_ptr->uri_path_len);
		if(!destination_header_ptr->uri_path_ptr)
		{
			sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
			return 0;
		}
		memcpy(destination_header_ptr->uri_path_ptr, source_header_ptr->uri_path_ptr, source_header_ptr->uri_path_len);
	}

	if(source_header_ptr->token_ptr)
	{
		destination_header_ptr->token_len = source_header_ptr->token_len;
		destination_header_ptr->token_ptr = sn_coap_protocol_malloc(source_header_ptr->token_len);
		if(!destination_header_ptr->token_ptr)
		{
			sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
			return 0;
		}
		memcpy(destination_header_ptr->token_ptr, source_header_ptr->token_ptr, source_header_ptr->token_len);
	}

	if(source_header_ptr->content_type_ptr)
	{
		destination_header_ptr->content_type_len = source_header_ptr->content_type_len;
		destination_header_ptr->content_type_ptr = sn_coap_protocol_malloc(source_header_ptr->content_type_len);
		if(!destination_header_ptr->content_type_ptr)
		{
			sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
			return 0;
		}
		memcpy(destination_header_ptr->content_type_ptr, source_header_ptr->content_type_ptr, source_header_ptr->content_type_len);
	}

	/* Options list */
	if(source_header_ptr->options_list_ptr)
	{
		destination_header_ptr->options_list_ptr = sn_coap_protocol_malloc(sizeof(sn_coap_options_list_s));
		if(!destination_header_ptr->options_list_ptr)
		{
			sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
			return 0;
		}
		memset(destination_header_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));


		if(source_header_ptr->options_list_ptr->max_age_ptr)
		{
			destination_header_ptr->options_list_ptr->max_age_len = source_header_ptr->options_list_ptr->max_age_len;
			destination_header_ptr->options_list_ptr->max_age_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->max_age_len);
			if(!destination_header_ptr->options_list_ptr->max_age_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->max_age_ptr, source_header_ptr->options_list_ptr->max_age_ptr, source_header_ptr->options_list_ptr->max_age_len);
		}

		if(source_header_ptr->options_list_ptr->proxy_uri_ptr)
		{
			destination_header_ptr->options_list_ptr->proxy_uri_len = source_header_ptr->options_list_ptr->proxy_uri_len;
			destination_header_ptr->options_list_ptr->proxy_uri_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->proxy_uri_len);
			if(!destination_header_ptr->options_list_ptr->proxy_uri_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->proxy_uri_ptr, source_header_ptr->options_list_ptr->proxy_uri_ptr, source_header_ptr->options_list_ptr->proxy_uri_len);
		}

		if(source_header_ptr->options_list_ptr->etag_ptr)
		{
			destination_header_ptr->options_list_ptr->etag_len = source_header_ptr->options_list_ptr->etag_len;
			destination_header_ptr->options_list_ptr->etag_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->etag_len);
			if(!destination_header_ptr->options_list_ptr->etag_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->etag_ptr, source_header_ptr->options_list_ptr->etag_ptr, source_header_ptr->options_list_ptr->etag_len);
		}

		if(source_header_ptr->options_list_ptr->uri_host_ptr)
		{
			destination_header_ptr->options_list_ptr->uri_host_len = source_header_ptr->options_list_ptr->uri_host_len;
			destination_header_ptr->options_list_ptr->uri_host_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->uri_host_len);
			if(!destination_header_ptr->options_list_ptr->uri_host_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->uri_host_ptr, source_header_ptr->options_list_ptr->uri_host_ptr, source_header_ptr->options_list_ptr->uri_host_len);
		}

		if(source_header_ptr->options_list_ptr->location_path_ptr)
		{
			destination_header_ptr->options_list_ptr->location_path_len = source_header_ptr->options_list_ptr->location_path_len;
			destination_header_ptr->options_list_ptr->location_path_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->location_path_len);
			if(!destination_header_ptr->options_list_ptr->location_path_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->location_path_ptr, source_header_ptr->options_list_ptr->location_path_ptr, source_header_ptr->options_list_ptr->location_path_len);
		}

		if(source_header_ptr->options_list_ptr->uri_port_ptr)
		{
			destination_header_ptr->options_list_ptr->uri_port_len = source_header_ptr->options_list_ptr->uri_port_len;
			destination_header_ptr->options_list_ptr->uri_port_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->uri_port_len);
			if(!destination_header_ptr->options_list_ptr->uri_port_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->uri_port_ptr, source_header_ptr->options_list_ptr->uri_port_ptr, source_header_ptr->options_list_ptr->uri_port_len);
		}

		if(source_header_ptr->options_list_ptr->location_query_ptr)
		{
			destination_header_ptr->options_list_ptr->location_query_len = source_header_ptr->options_list_ptr->location_query_len;
			destination_header_ptr->options_list_ptr->location_query_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->location_query_len);
			if(!destination_header_ptr->options_list_ptr->location_query_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->location_query_ptr, source_header_ptr->options_list_ptr->location_query_ptr, source_header_ptr->options_list_ptr->location_query_len);
		}

		if(source_header_ptr->options_list_ptr->observe_ptr)
		{
			destination_header_ptr->options_list_ptr->observe_len = source_header_ptr->options_list_ptr->observe_len;
			destination_header_ptr->options_list_ptr->observe_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->observe_len);
			if(!destination_header_ptr->options_list_ptr->observe_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->observe_ptr, source_header_ptr->options_list_ptr->observe_ptr, source_header_ptr->options_list_ptr->observe_len);
		}

		if(source_header_ptr->options_list_ptr->accept_ptr)
		{
			destination_header_ptr->options_list_ptr->accept_len = source_header_ptr->options_list_ptr->accept_len;
			destination_header_ptr->options_list_ptr->accept_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->accept_len);
			if(!destination_header_ptr->options_list_ptr->accept_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->accept_ptr, source_header_ptr->options_list_ptr->accept_ptr, source_header_ptr->options_list_ptr->accept_len);
		}

		if(source_header_ptr->options_list_ptr->uri_query_ptr)
		{
			destination_header_ptr->options_list_ptr->uri_query_len = source_header_ptr->options_list_ptr->uri_query_len;
			destination_header_ptr->options_list_ptr->uri_query_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->uri_query_len);
			if(!destination_header_ptr->options_list_ptr->uri_query_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->uri_query_ptr, source_header_ptr->options_list_ptr->uri_query_ptr, source_header_ptr->options_list_ptr->uri_query_len);
		}

		if(source_header_ptr->options_list_ptr->block1_ptr)
		{
			destination_header_ptr->options_list_ptr->block1_len = source_header_ptr->options_list_ptr->block1_len;
			destination_header_ptr->options_list_ptr->block1_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->block1_len);
			if(!destination_header_ptr->options_list_ptr->block1_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->block1_ptr, source_header_ptr->options_list_ptr->block1_ptr, source_header_ptr->options_list_ptr->block1_len);
		}

		if(source_header_ptr->options_list_ptr->block2_ptr)
		{
			destination_header_ptr->options_list_ptr->block2_len = source_header_ptr->options_list_ptr->block2_len;
			destination_header_ptr->options_list_ptr->block2_ptr = sn_coap_protocol_malloc(source_header_ptr->options_list_ptr->block2_len);
			if(!destination_header_ptr->options_list_ptr->block2_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(destination_header_ptr);
				return 0;
			}
			memcpy(destination_header_ptr->options_list_ptr->block2_ptr, source_header_ptr->options_list_ptr->block2_ptr, source_header_ptr->options_list_ptr->block2_len);
		}
	}

	return destination_header_ptr;
}
#endif
