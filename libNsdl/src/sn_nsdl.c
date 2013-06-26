/**
 * \file sn_nsdl.c
 *
 * \brief Nano service device library
 *
 *	Application interface to CoAP, GRS and NSP handling.
 *
 */

#include <string.h>

#include "nsdl_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_nsdl_lib.h"
#include "sn_grs.h"
#include "sn_linked_list.h"

/* Constants */
SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t 	ep_name_parameter_string[] 	= EP_NAME_PARAMETERS;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		resource_path_ptr[]			= RESOURCE_DIR_PATH;

uint8_t 	nsp_ipv6_addr[16]			= {0x20,0x01,0x04,0x70,0x10,0x02,0x00,0x11,0x00,0x00,0x00,0x00,0x00,0x54,0x20,0x01};

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		resource_type_parameter[]	= RT_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		obs_parameter[]				= OBS_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		if_description_parameter[]	= IF_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		ep_contex_parameter[]		= CON_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t		ep_lifetime_parameter[]		= LT_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t 	coap_con_type_parameter[]	= COAP_CON_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
uint8_t 	event_path_parameter[]		= EVENT_PATH;

/* Global function pointers */
void 	*(*sn_nsdl_alloc)(uint16_t)  = 0;
void 	(*sn_nsdl_free)(void*) = 0;
uint8_t (*sn_nsdl_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *) = 0;
uint8_t (*sn_nsdl_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *) = 0;

/* Global variables */
sn_nsdl_ep_parameters_s		*ep_information_ptr  = 0; 	// Endpoint parameters, Name, Domain etc..
sn_nsdl_addr_s 				*nsp_address_ptr = 0;		// NSP server address information
sn_linked_list_t			*message_list_ptr = 0;		//
static uint8_t sn_nsdl_endpoint_registered = 0;

/* Function prototypes */
static int8_t 			sn_nsdl_internal_coap_send					(sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr, uint8_t message_description);
static void				sn_nsdl_resolve_nsp_address					(void);
int8_t 					sn_nsdl_build_registration_body				(sn_coap_hdr_s *message_ptr, uint8_t updating_registeration);
static uint16_t 		sn_nsdl_calculate_registration_body_size	(uint8_t updating_registeration);
static uint8_t 			sn_nsdl_calculate_uri_query_option_len		(sn_nsdl_ep_parameters_s *endpoint_info_ptr, uint8_t msg_type);
static int8_t 			sn_nsdl_fill_uri_query_options				(sn_nsdl_ep_parameters_s *parameter_ptr, sn_coap_hdr_s *source_msg_ptr, uint8_t msg_type);
static int8_t			sn_nsdl_local_rx_function					(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr);
static int8_t 			sn_nsdl_resolve_ep_information				(sn_coap_hdr_s *coap_packet_ptr);
static void 			sn_nsdl_mark_resources_as_registered		(void);
static uint8_t 			sn_nsdl_itoa_len							(uint8_t value);
static uint8_t 			*sn_nsdl_itoa								(uint8_t *ptr, uint8_t value);

//static const char version_array[] = {SVN_REV};
//
//extern const char __code* sn_nsdl_get_library_version_info(void)
//{
//
//	return (const char __code*) version_array;
//}


/**
 * \fn extern int8_t sn_nsdl_destroy(void)
 *
 *
 * \brief Initialization function for NSDL library. Initializes NSDL, GRS, HTTP and CoAP.
 *
 * \return Returns always  SN_NSDL_SUCCESS (0)
 */
extern int8_t sn_nsdl_destroy(void)
{
	if(message_list_ptr)
	{
		uint16_t size =  sn_linked_list_count_nodes(message_list_ptr);
		uint16_t i = 0;
		sn_nsdl_sent_messages_s*tmp;


		for(i=0;i<size;i++)
		{
			tmp = sn_linked_list_get_first_node(message_list_ptr);

			if(tmp)
			{
				sn_linked_list_remove_current_node(message_list_ptr);
				sn_nsdl_free(tmp);
				tmp = 0;
			}
		}

		if(!sn_linked_list_count_nodes(message_list_ptr))
		{
			sn_linked_list_free(message_list_ptr);
			message_list_ptr = 0;
		}
	}

	if(ep_information_ptr)
	{
		if(ep_information_ptr->endpoint_name_ptr)
		{
			sn_nsdl_free(ep_information_ptr->endpoint_name_ptr);
			ep_information_ptr->endpoint_name_ptr = 0;
		}
		if(ep_information_ptr->domain_name_ptr)
		{
			sn_nsdl_free(ep_information_ptr->domain_name_ptr);
			ep_information_ptr->domain_name_ptr = 0;
			ep_information_ptr->domain_name_len = 0;
		}
		if(ep_information_ptr->type_ptr)
		{
			sn_nsdl_free(ep_information_ptr->type_ptr);
			ep_information_ptr->type_ptr = 0;
		}
		if(ep_information_ptr->contex_ptr)
		{
			sn_nsdl_free(ep_information_ptr->contex_ptr);
			ep_information_ptr->contex_ptr = 0;
		}
		if(ep_information_ptr->lifetime_ptr)

		{
			sn_nsdl_free(ep_information_ptr->lifetime_ptr);
			ep_information_ptr->lifetime_ptr = 0;
		}

		sn_nsdl_free(ep_information_ptr);
		ep_information_ptr = 0;
	}

	if(nsp_address_ptr)
	{
		if(nsp_address_ptr->socket_information)
		{
			sn_nsdl_free(nsp_address_ptr->socket_information);
			nsp_address_ptr->socket_information= 0;
		}

		if(nsp_address_ptr->addr_ptr)
		{
			sn_nsdl_free(nsp_address_ptr->addr_ptr);
			nsp_address_ptr->addr_ptr = 0;
		}
		sn_nsdl_free(nsp_address_ptr);
		nsp_address_ptr = 0;
	}

	/* Destroy also libCoap and grs part of libNsdl */
	sn_grs_destroy();
	sn_coap_protocol_destroy();

	return 0;
}

/**
 * \fn extern int8_t sn_nsdl_init	(uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
 *							uint8_t (*sn_nsdl_rx_cb)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
 *							sn_nsdl_mem_s *sn_memory)
 *
 *
 * \brief Initialization function for NSDL library. Initializes NSDL, GRS, HTTP and CoAP.
 *
 * \param *sn_nsdl_tx_callback 	A callback function for sending messages.
 *
 * \param *sn_nsdl_rx_callback 	A callback function for parsed messages. If received message is not CoAP protocol message (eg. ACK), message for GRS (GET, PUT, POST, DELETE) or
 * 								reply for some NSDL message (register message etc.), rx callback will be called.
 *
 * \param *sn_memory			Memory structure which includes function pointers to the allocation and free functions.
 *
 * \return						SN_NSDL_SUCCESS = 0, Failed = -1
 */

extern int8_t sn_nsdl_init	(uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
							uint8_t (*sn_nsdl_rx_cb)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
							sn_nsdl_mem_s *sn_memory)
{
	/* Check pointers and define function pointers */
	if(!sn_memory || !sn_memory->sn_nsdl_alloc || !sn_memory->sn_nsdl_free || !sn_nsdl_tx_cb || !sn_nsdl_rx_cb)
		return SN_NSDL_FAILURE;

	/* Define function pointers */
	sn_nsdl_alloc = sn_memory->sn_nsdl_alloc;
	sn_nsdl_free = sn_memory->sn_nsdl_free;

	sn_nsdl_tx_callback = sn_nsdl_tx_cb;
	sn_nsdl_rx_callback = sn_nsdl_rx_cb;

	sn_linked_list_init(sn_nsdl_alloc, sn_nsdl_free);

	message_list_ptr = sn_linked_list_create();
	if(!message_list_ptr)
		return SN_NSDL_FAILURE;

	/* Initialize ep parameters struct */
	if(!ep_information_ptr)
	{
		ep_information_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_ep_parameters_s));
		if(!ep_information_ptr)
		{
			sn_linked_list_free(message_list_ptr);
			return SN_NSDL_FAILURE;
		}
		memset(ep_information_ptr, 0, sizeof(sn_nsdl_ep_parameters_s));
	}

	/* Initialize GRS */
	if(sn_grs_init(sn_nsdl_tx_cb,&sn_nsdl_local_rx_function, sn_memory))
	{

		sn_nsdl_free(ep_information_ptr);
		ep_information_ptr = 0;
		sn_linked_list_free(message_list_ptr);
		return SN_NSDL_FAILURE;

	}

	// todo: Resolve NS server address -> v0.5 = hardcoded address
	sn_nsdl_resolve_nsp_address();

	sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;

	return SN_NSDL_SUCCESS;
}

extern int8_t sn_nsdl_GET_with_QUERY(char * uri, uint16_t urilen, uint8_t*destination, uint16_t port, char *query, uint8_t query_len)
{
	sn_coap_hdr_s 	*message_ptr;
	sn_nsdl_addr_s *dst = 0;

	message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(message_ptr == NULL)
		return SN_NSDL_FAILURE;

	memset(message_ptr, 0, sizeof(sn_coap_hdr_s));

	/* Fill message fields -> confirmable post to specified NSP path */
	message_ptr->msg_type 	= 	COAP_MSG_TYPE_CONFIRMABLE;
	message_ptr->msg_code 	= 	COAP_MSG_CODE_REQUEST_GET;
	/* Allocate memory for the extended options list */
	message_ptr->options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(message_ptr->options_list_ptr == NULL)
	{
		sn_nsdl_free(message_ptr);
		message_ptr = 0;
		return SN_NSDL_FAILURE;
	}


	memset(message_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
	message_ptr->options_list_ptr->uri_query_len =query_len;
	message_ptr->options_list_ptr->uri_query_ptr = (uint8_t *)query;
	message_ptr->uri_path_len = urilen;
	message_ptr->uri_path_ptr = (uint8_t *)uri;

	/* Build and send coap message to NSP */
	/* Local variables */
	if(!dst)
	{
		//allocate only if previously not allocated
		dst = sn_nsdl_alloc(sizeof(sn_nsdl_addr_s));
	}

	if(dst)
	{
		/* This is only for version 0.5 */
		dst->type = SN_NSDL_ADDRESS_TYPE_IPV6;
		dst->port = port;
		dst->addr_len = 16;
		if(!dst->addr_ptr)
		{
			dst->addr_ptr = sn_nsdl_alloc(dst->addr_len);
			memcpy(dst->addr_ptr, destination, 16);
		}
	}
	sn_nsdl_internal_coap_send(message_ptr, dst, SN_NSDL_MSG_NO_TYPE);

	if(dst->addr_ptr)
		sn_nsdl_free(dst->addr_ptr);

	if(dst)
		sn_nsdl_free(dst);
	message_ptr->uri_path_ptr = NULL;
	message_ptr->options_list_ptr->uri_host_ptr = NULL;
	message_ptr->options_list_ptr->uri_query_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(message_ptr);
	return SN_NSDL_SUCCESS;
}

extern int8_t sn_nsdl_GET(char * uri, uint16_t urilen, uint8_t*destination, uint16_t port)
{
	sn_coap_hdr_s 	*message_ptr;
	sn_nsdl_addr_s *dst = 0;


	message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(message_ptr == NULL)
		return SN_NSDL_FAILURE;

	memset(message_ptr, 0, sizeof(sn_coap_hdr_s));

	/* Fill message fields -> confirmable post to specified NSP path */
	message_ptr->msg_type 	= 	COAP_MSG_TYPE_CONFIRMABLE;
	message_ptr->msg_code 	= 	COAP_MSG_CODE_REQUEST_GET;
	/* Allocate memory for the extended options list */
	message_ptr->options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(message_ptr->options_list_ptr == NULL)
	{
		sn_nsdl_free(message_ptr);
		message_ptr = 0;
		return SN_NSDL_FAILURE;
	}


	memset(message_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

	message_ptr->uri_path_len = urilen;
	message_ptr->uri_path_ptr = (uint8_t *)uri;

	/* Build and send coap message to NSP */
	/* Local variables */
	if(!dst)
	{
		//allocate only if previously not allocated
		dst = sn_nsdl_alloc(sizeof(sn_nsdl_addr_s));
		memset(dst, 0, sizeof(sn_nsdl_addr_s));
	}

	if(dst)
	{
		/* This is only for version 0.5 */
		dst->type = SN_NSDL_ADDRESS_TYPE_IPV6;
		dst->port = port;
		dst->addr_len = 16;
		if(!dst->addr_ptr)
		{
			dst->addr_ptr = sn_nsdl_alloc(dst->addr_len);
			memcpy(dst->addr_ptr, destination, 16);
		}
	}
	sn_nsdl_internal_coap_send(message_ptr, dst, SN_NSDL_MSG_NO_TYPE);

	if(dst->addr_ptr)
		sn_nsdl_free(dst->addr_ptr);
	if(dst)
		sn_nsdl_free(dst);
	message_ptr->uri_path_ptr = NULL;
	message_ptr->options_list_ptr->uri_host_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(message_ptr);
	return SN_NSDL_SUCCESS;
}


/**
 * \fn extern uint8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr)
 *
 *
 * \brief Registers endpoint to NSP server.
 *
 * \param *endpoint_info_ptr	Contains endpoint information.
 *
 * \return						SN_NSDL_SUCCESS = 0, Failed = -1
 */
extern int8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr)
{
	/* Local variables */
	sn_coap_hdr_s 	*register_message_ptr;
	int8_t			status 					= 0;

	if(!endpoint_info_ptr)
		return SN_NSDL_FAILURE;

	/*** Build endpoint register message ***/

	/* Allocate memory for header struct */
	register_message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(register_message_ptr == NULL)
		return SN_NSDL_FAILURE;

	memset(register_message_ptr, 0, sizeof(sn_coap_hdr_s));

	/* Fill message fields -> confirmable post to specified NSP path */
	register_message_ptr->msg_type 	= 	COAP_MSG_TYPE_CONFIRMABLE;
	register_message_ptr->msg_code 	= 	COAP_MSG_CODE_REQUEST_POST;

	/* Allocate memory for the extended options list */
	register_message_ptr->options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(register_message_ptr->options_list_ptr == NULL)
	{
		sn_nsdl_free(register_message_ptr);
		register_message_ptr = 0;
		return SN_NSDL_FAILURE;
	}

	memset(register_message_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

	register_message_ptr->uri_path_len = sizeof(resource_path_ptr);
	register_message_ptr->uri_path_ptr = resource_path_ptr;

	/* If domain name is configured, fill needed fields */
	if(endpoint_info_ptr->domain_name_len)
	{
		register_message_ptr->options_list_ptr->uri_host_len = endpoint_info_ptr->domain_name_len;
		register_message_ptr->options_list_ptr->uri_host_ptr = endpoint_info_ptr->domain_name_ptr;
	}

	/* Fill Uri-query options */
	sn_nsdl_fill_uri_query_options(endpoint_info_ptr, register_message_ptr, SN_NSDL_EP_REGISTER_MESSAGE);
#ifndef REG_TEMPLATE
	/* Built body for message */
	status = sn_nsdl_build_registration_body(register_message_ptr, 0);
	if(status == SN_NSDL_FAILURE)
	{ 
		register_message_ptr->uri_path_ptr = NULL;
		register_message_ptr->options_list_ptr->uri_host_ptr = NULL;
		sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);
		return SN_NSDL_FAILURE;
	}
#endif
	/* Build and send coap message to NSP */
	status = sn_nsdl_internal_coap_send(register_message_ptr, nsp_address_ptr, SN_NSDL_MSG_REGISTER);

	if(register_message_ptr->payload_ptr)
	{
		sn_nsdl_free(register_message_ptr->payload_ptr);
		register_message_ptr->payload_ptr = NULL;
	}

	register_message_ptr->uri_path_ptr = NULL;
	register_message_ptr->options_list_ptr->uri_host_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);

	if(ep_information_ptr)
	{
		if(ep_information_ptr->domain_name_ptr)
		{
			sn_nsdl_free(ep_information_ptr->domain_name_ptr);
			ep_information_ptr->domain_name_ptr = 0;
			ep_information_ptr->domain_name_len = 0;
		}

		if(ep_information_ptr->endpoint_name_ptr)
		{
			sn_nsdl_free(ep_information_ptr->endpoint_name_ptr);
			ep_information_ptr->endpoint_name_ptr = 0;
			ep_information_ptr->endpoint_name_len = 0;
		}

		if(endpoint_info_ptr->domain_name_ptr)
		{

			if(!ep_information_ptr->domain_name_ptr)
			{
				ep_information_ptr->domain_name_ptr = sn_nsdl_alloc(endpoint_info_ptr->domain_name_len);
			}
			if(!ep_information_ptr->domain_name_ptr)
			{
				return SN_NSDL_FAILURE;
			}

			memcpy(ep_information_ptr->domain_name_ptr, endpoint_info_ptr->domain_name_ptr, endpoint_info_ptr->domain_name_len);
			ep_information_ptr->domain_name_len = endpoint_info_ptr->domain_name_len;

		}

		if(endpoint_info_ptr->endpoint_name_ptr)
		{

			if(!ep_information_ptr->endpoint_name_ptr)
			{
				ep_information_ptr->endpoint_name_ptr = sn_nsdl_alloc(endpoint_info_ptr->endpoint_name_len);
			}
			if(!ep_information_ptr->endpoint_name_ptr)
			{
				if(ep_information_ptr->domain_name_ptr)
				{
					sn_nsdl_free(ep_information_ptr->domain_name_ptr);
					ep_information_ptr->domain_name_ptr  = 0;
					ep_information_ptr->domain_name_len = 0;
				}
				return SN_NSDL_FAILURE;
			}

			memcpy(ep_information_ptr->endpoint_name_ptr, endpoint_info_ptr->endpoint_name_ptr, endpoint_info_ptr->endpoint_name_len);
			ep_information_ptr->endpoint_name_len = endpoint_info_ptr->endpoint_name_len;

		}
	}

	return status;
}

/**
 * \fn extern int8_t sn_nsdl_unregister_endpoint(void)
 *
 *
 * \brief Sends unregister-message to NSP server.
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
extern int8_t sn_nsdl_unregister_endpoint(void)
{
	/* Local variables */
	sn_coap_hdr_s  	*unregister_message_ptr;
	uint8_t			*temp_ptr = 0;

	/* Check that EP have been registered */
	if(sn_nsdl_is_ep_registered())
	{

		/* Memory allocation for unregister message */
		unregister_message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
		if(!unregister_message_ptr)
			return SN_NSDL_FAILURE;

		memset(unregister_message_ptr, 0, sizeof(sn_coap_hdr_s));

		/* Fill unregister message */
		unregister_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
		unregister_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_DELETE;

		unregister_message_ptr->uri_path_len = (RESOURCE_DIR_LEN + 1 + ep_information_ptr->domain_name_len + 1 + ep_information_ptr->endpoint_name_len);
		unregister_message_ptr->uri_path_ptr = sn_nsdl_alloc(unregister_message_ptr->uri_path_len);
		if (!unregister_message_ptr->uri_path_ptr)
		{
			sn_coap_parser_release_allocated_coap_msg_mem(unregister_message_ptr);
			return SN_NSDL_FAILURE;
		}

		temp_ptr = unregister_message_ptr->uri_path_ptr;

		memcpy(temp_ptr,resource_path_ptr, RESOURCE_DIR_LEN);
		temp_ptr += RESOURCE_DIR_LEN;

		*temp_ptr++ = '/';

		memcpy(temp_ptr ,ep_information_ptr->domain_name_ptr, ep_information_ptr->domain_name_len);
		temp_ptr += ep_information_ptr->domain_name_len;

		*temp_ptr++ = '/';

		memcpy(temp_ptr ,ep_information_ptr->endpoint_name_ptr, ep_information_ptr->endpoint_name_len);

		/* Send message */
		sn_nsdl_internal_coap_send(unregister_message_ptr, nsp_address_ptr, SN_NSDL_MSG_UNREGISTER);

		/* Free memory */
		sn_coap_parser_release_allocated_coap_msg_mem(unregister_message_ptr);

	}

	return SN_NSDL_SUCCESS;
}

/**
 * \fn extern int8_t sn_nsdl_update_registration (sn_nsdl_ep_parameters_s *endpoint_info_ptr)
 *
 *
 * \brief Sends endpoint registration update to NSP server.
 *
 * \param *endpoint_info_ptr	Contains endpoint information
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
extern int8_t sn_nsdl_update_registration (sn_nsdl_ep_parameters_s *endpoint_info_ptr)
{
	/* Local variables */
	sn_coap_hdr_s 	*register_message_ptr;
	uint8_t			*temp_ptr;

	/*** Build endpoint register update message ***/

	/* Allocate memory for header struct */
	register_message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(register_message_ptr == NULL)
		return SN_NSDL_FAILURE;

	memset(register_message_ptr, 0, sizeof(sn_coap_hdr_s));

	/* Fill message fields -> confirmable post to specified NSP path */
	register_message_ptr->msg_type 	= 	COAP_MSG_TYPE_CONFIRMABLE;
	register_message_ptr->msg_code 	= 	COAP_MSG_CODE_REQUEST_PUT;

	register_message_ptr->uri_path_len 	= 	sizeof(resource_path_ptr) + ep_information_ptr->domain_name_len + ep_information_ptr->endpoint_name_len + 2; 	// = rd/domain/endpoint

	register_message_ptr->uri_path_ptr 	= 	sn_nsdl_alloc(register_message_ptr->uri_path_len);
	if(!register_message_ptr->uri_path_ptr)
	{
		sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);
		return SN_NSDL_FAILURE;
	}

	temp_ptr = register_message_ptr->uri_path_ptr;

	/* rd/ */
	memcpy(temp_ptr, resource_path_ptr, sizeof(resource_path_ptr));
	temp_ptr += sizeof(resource_path_ptr);
	*temp_ptr++ = '/';

	/* rd/DOMAIN/ */
	memcpy(temp_ptr, ep_information_ptr->domain_name_ptr, ep_information_ptr->domain_name_len);
	temp_ptr += ep_information_ptr->domain_name_len;
	*temp_ptr++ = '/';

	/* rd/domain/ENDPOINT */
	memcpy(temp_ptr, ep_information_ptr->endpoint_name_ptr, ep_information_ptr->endpoint_name_len);


	/* Allocate memory for the extended options list */
	register_message_ptr->options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(register_message_ptr->options_list_ptr == NULL)
	{
		sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);
		return SN_NSDL_FAILURE;
	}

	memset(register_message_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

	/* Fill Uri-query options */
	sn_nsdl_fill_uri_query_options(endpoint_info_ptr, register_message_ptr, SN_NSDL_EP_UPDATE_MESSAGE);

	/* Build and send coap message to NSP */
	sn_nsdl_internal_coap_send(register_message_ptr, nsp_address_ptr, SN_NSDL_MSG_UPDATE);

	if(register_message_ptr->payload_ptr)
		sn_nsdl_free(register_message_ptr->payload_ptr);
	sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);

	return SN_NSDL_SUCCESS;
}

/**
 * \fn extern int8_t sn_nsdl_send_eventing_message (uint8_t *event_name_ptr, uint16_t event_name_len, uint8_t *message_body_ptr, uint16_t message_body_len)
 *
 *
 * \brief Send eventing message to NSP server.
 *
 * \param *event_name_ptr	Event name pointer. The event name is added to the URL /event/{event-name}
 * \param event_name_len	Event name length.
 * \param *message_body_ptr	Event content pointer. Event content is delivered in the message body.
 * \param message_body_len	Event content length.
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
extern int8_t sn_nsdl_send_eventing_message (uint8_t *event_name_ptr, uint16_t event_name_len, uint8_t *message_body_ptr, uint16_t message_body_len)
{
	sn_coap_hdr_s 	*eventing_message_ptr;
	int8_t			status = 0;

	/* Allocate and initialize memory for header struct */
	eventing_message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(eventing_message_ptr == NULL)
		return SN_NSDL_FAILURE;

	memset(eventing_message_ptr, 0, sizeof(sn_coap_hdr_s));

	/* Fill header */
	eventing_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
	eventing_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;

	/* Fill uri path option */
	eventing_message_ptr->uri_path_len = sizeof(event_path_parameter) + event_name_len;
	eventing_message_ptr->uri_path_ptr = sn_nsdl_alloc(eventing_message_ptr->uri_path_len);

	if(!eventing_message_ptr->uri_path_ptr)
	{
		sn_coap_parser_release_allocated_coap_msg_mem(eventing_message_ptr);
		return SN_NSDL_FAILURE;
	}

	memcpy(eventing_message_ptr->uri_path_ptr, event_path_parameter, sizeof(event_path_parameter));
	memcpy(eventing_message_ptr->uri_path_ptr + sizeof(event_path_parameter), event_name_ptr, event_name_len);

	/* Fill payload */
	eventing_message_ptr->payload_len = message_body_len;
	eventing_message_ptr->payload_ptr = message_body_ptr;

	/* Send coap message */
	status = sn_nsdl_internal_coap_send(eventing_message_ptr, nsp_address_ptr, SN_NSDL_MSG_EVENT);

	eventing_message_ptr->payload_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(eventing_message_ptr);

	return status;
}

/**
 * \fn extern void sn_nsdl_nsp_lost(void)
 *
 *
 * \brief Sets endpoint registration status to SN_NSDL_ENDPOINT_NOT_REGISTERED.
 *
 */
extern void sn_nsdl_nsp_lost(void)
{
	sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;
	return;
}

/**
 * \fn extern int8_t sn_nsdl_is_ep_registered(void)
 *
 *
 * \brief Checks if endpoint is registered.
 *
 * \return 1 if endpointi registration is done SN_NSDL_SUCCESSfully, 0 if endpoint is not registered
 */
extern int8_t sn_nsdl_is_ep_registered(void)
{
//	if(ep_information_ptr->endpoint_name_ptr)
//		return 1;
//	else
//		return 0;
	return sn_nsdl_endpoint_registered;
}

/**
 * \fn extern int8_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
 *															uint8_t *payload_ptr, uint16_t payload_len,
 *															uint8_t *observe_ptr, uint8_t observe_len,
 *															sn_coap_msg_type_e message_type)
 *
 *
 * \brief Sends observation message to NSP server
 *
 * \param *token_ptr	Pointer to token to be used
 * \param token_len		Token length
 * \param *payload_ptr	Pointer to payload to be sent
 * \param payload_len	Payload length
 * \param *observe_ptr	Pointer to observe number to be sent
 * \param observe_len	Observe number len
 * \param message_type	Observation message type (confirmable or non-confirmable)
 * \param contetnt_type	Observation message payload contetnt type
 *
 * \return		If success, returns observation messages message ID = 0, if failed, returns 0.
 */
extern uint16_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
													uint8_t *payload_ptr, uint16_t payload_len,
													uint8_t *observe_ptr, uint8_t observe_len,
													sn_coap_msg_type_e message_type, uint8_t content_type)
{
	sn_coap_hdr_s 	*notification_message_ptr;
	uint16_t		return_msg_id = 0;

	/* Allocate and initialize memory for header struct */
	notification_message_ptr = sn_nsdl_alloc(sizeof(sn_coap_hdr_s));
	if(notification_message_ptr == NULL)
		return 0;

	memset(notification_message_ptr, 0, sizeof(sn_coap_hdr_s));

	notification_message_ptr->options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(notification_message_ptr->options_list_ptr  == NULL)
	{
		sn_nsdl_free(notification_message_ptr);
		return 0;
	}

	memset(notification_message_ptr->options_list_ptr , 0, sizeof(sn_coap_options_list_s));

	/* Fill header */
	notification_message_ptr->msg_type = message_type;
	notification_message_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;

	/* Fill token */
	notification_message_ptr->token_len = token_len;
	notification_message_ptr->token_ptr = token_ptr;

	/* Fill payload */
	notification_message_ptr->payload_len = payload_len;
	notification_message_ptr->payload_ptr = payload_ptr;

	/* Fill observe */
	notification_message_ptr->options_list_ptr->observe_len = observe_len;
	notification_message_ptr->options_list_ptr->observe_ptr = observe_ptr;

	/* Fill content type */
	if(content_type)
	{
		notification_message_ptr->content_type_len = 1;
		notification_message_ptr->content_type_ptr = &content_type;
	}

	/* Send message */
	if(sn_nsdl_internal_coap_send(notification_message_ptr, nsp_address_ptr, SN_NSDL_MSG_NO_TYPE) == SN_NSDL_FAILURE)
		return_msg_id = 0;
	else
		return_msg_id = notification_message_ptr->msg_id;

	/* Free memory */

	notification_message_ptr->payload_ptr = NULL;
	notification_message_ptr->options_list_ptr->observe_ptr = NULL;
	notification_message_ptr->token_ptr = NULL;
	notification_message_ptr->content_type_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(notification_message_ptr);

	return return_msg_id;
}


/* * * * * * * * * * * * * * * * * * * * * */
/* 			GRS Wrapper					   */
/* These are documented in sn_grs.c - file */
/* * * * * * * * * * * * * * * * * * * * * */

int16_t sn_nsdl_get_capability(void)
{
	return sn_grs_get_capability();
}


uint32_t sn_nsdl_get_version(void)
{
	return sn_grs_get_version();
}


int8_t sn_nsdl_process_http(uint8_t *packet_ptr, uint16_t *packet_len_ptr, sn_nsdl_addr_s *src_ptr)
{
	return sn_grs_process_http(packet_ptr, packet_len_ptr, src_ptr);
}


int8_t sn_nsdl_process_coap(uint8_t *packet_ptr, uint16_t packet_len_ptr, sn_nsdl_addr_s *src_ptr)
{
	return sn_grs_process_coap(packet_ptr, packet_len_ptr, src_ptr);
}

int8_t sn_nsdl_exec(uint32_t time)
{
	return sn_grs_exec(time);
}

int8_t sn_nsdl_create_resource(sn_nsdl_resource_info_s *res_ptr)
{
	return sn_grs_create_resource(res_ptr);
}

int8_t sn_nsdl_update_resource(sn_nsdl_resource_info_s *res_ptr)
{
	return sn_grs_update_resource(res_ptr);
}

int8_t sn_nsdl_delete_resource(uint8_t pathlen, uint8_t *path_ptr)
{
	return sn_grs_delete_resource(pathlen, path_ptr);
}

sn_nsdl_resource_info_s *sn_nsdl_get_resource(uint8_t pathlen, uint8_t *path_ptr)
{
	return sn_grs_get_resource(pathlen, path_ptr);
}

sn_grs_resource_list_s *sn_nsdl_list_resource(uint8_t pathlen, uint8_t *path_ptr)
{
	return sn_grs_list_resource(pathlen, path_ptr);
}

int8_t sn_nsdl_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr)
{
	return sn_grs_send_coap_message(address_ptr, coap_hdr_ptr);
}

/********************/
/* Static functions */
/********************/


/**
 * \fn static int8_t sn_nsdl_send_coap_message(sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr, uint8_t message_description)
 *
 *
 * \brief To send NSDL messages. Stores message id?s and message description to catch response from NSP server
 *
 * \param	*coap_header_ptr	Pointer to the CoAP message header to be sent
 * \param	*dst_addr_ptr		Pointer to the address structure that contains destination address information
 * \param	message_description Message description to be stored to list for waiting response
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_internal_coap_send(sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr, uint8_t message_description)
{
	uint8_t 					*coap_message_ptr 	= NULL;
	uint16_t 					coap_message_len 	= 0;
	int16_t 						status 				= 0;

	coap_message_len = sn_coap_builder_calc_needed_packet_data_size(coap_header_ptr);

	if(coap_message_len == 0)
		return SN_NSDL_FAILURE;

	coap_message_ptr = sn_nsdl_alloc(coap_message_len);
	if(!coap_message_ptr)
		return SN_NSDL_FAILURE;

	/* Build message */
	status = sn_coap_protocol_build(dst_addr_ptr,coap_message_ptr, coap_header_ptr);

	/* If message building failed */
	if(status < 0)
	{
		sn_nsdl_free(coap_message_ptr);
		return SN_NSDL_FAILURE;
	}

	/* If mesage type is confirmable, save it to list to wait for reply */
	if(coap_header_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
	{
		sn_nsdl_sent_messages_s *message_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_sent_messages_s));
		if(message_ptr)
		{
			if(sn_linked_list_count_nodes(message_list_ptr) >= SN_NSDL_MAX_MESSAGE_COUNT)
			{
				sn_nsdl_sent_messages_s *message_temp_ptr = sn_linked_list_get_last_node(message_list_ptr);
				if(message_temp_ptr)
					sn_nsdl_free(message_temp_ptr);
				sn_linked_list_remove_current_node(message_list_ptr);
			}

			message_ptr->message_type = message_description;
			message_ptr->msg_id_number = coap_header_ptr->msg_id;
			sn_linked_list_add_node(message_list_ptr, (void*)message_ptr);

			status = SN_NSDL_SUCCESS;
		}
		else
		{
			status = SN_NSDL_FAILURE;
		}

	}

	sn_nsdl_tx_callback(SN_NSDL_PROTOCOL_COAP, coap_message_ptr, coap_message_len, dst_addr_ptr);
	sn_nsdl_free(coap_message_ptr);

	return status;
}

/**
 * \fn static void sn_nsdl_resolve_nsp_address(void)
 *
 * \brief Resolves NSP server address.
 *
 * \note this is only for testing purposes - NSP address is hardcoded
 */
static void sn_nsdl_resolve_nsp_address(void)
{
	/* Local variables */
	if(!nsp_address_ptr)
	{
		//allocate only if previously not allocated
		nsp_address_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_addr_s));
	}

	if(nsp_address_ptr)
	{
		memset(nsp_address_ptr, 0, sizeof(sn_nsdl_addr_s));
		/* This is only for version 0.5 */
		nsp_address_ptr->type = SN_NSDL_ADDRESS_TYPE_IPV6;
		nsp_address_ptr->port = 5683;
		nsp_address_ptr->addr_len = 16;
		if(!nsp_address_ptr->addr_ptr)
		{
			nsp_address_ptr->addr_ptr = sn_nsdl_alloc(nsp_address_ptr->addr_len);
		}
	}

	/* Todo: get NSP address */
}

/**
 * \fn static int8_t sn_nsdl_build_registration_body(sn_coap_hdr_s *message_ptr)
 *
 * \brief 	To build GRS resources to registration message payload
 *
 * \param	*message_ptr Pointer to CoAP message header
 *
 * \return	SN_NSDL_SUCCESS = 0, Failed = -1
 */
int8_t sn_nsdl_build_registration_body(sn_coap_hdr_s *message_ptr, uint8_t updating_registeration)
{
	/* Local variables */
	uint8_t					*temp_ptr;
	sn_nsdl_resource_info_s 	*resource_temp_ptr;


	/* Get list of resources */


	/* Calculate needed memory and allocate */
	message_ptr->payload_len = sn_nsdl_calculate_registration_body_size(updating_registeration);

	/* If no resources to be registered, return SN_NSDL_SUCCESS */
	if(!message_ptr->payload_len)
	{
		return SN_NSDL_SUCCESS;
	}

	message_ptr->payload_ptr = sn_nsdl_alloc(message_ptr->payload_len);
	if(!message_ptr->payload_ptr)
	{
		return SN_NSDL_FAILURE;
	}

	/* Build message */
	temp_ptr = message_ptr->payload_ptr;

	resource_temp_ptr = sn_grs_get_first_resource();

	/* Loop trough all resources */
	while(resource_temp_ptr)
	{

		/* if resource needs to be registered */
		if(resource_temp_ptr->resource_parameters_ptr)
		{

			if(updating_registeration && resource_temp_ptr->resource_parameters_ptr->registered == SN_NDSL_RESOURCE_REGISTERED)
			{
				resource_temp_ptr = sn_grs_get_next_resource();
				continue;
			}
			else
			{
				resource_temp_ptr->resource_parameters_ptr->registered = SN_NDSL_RESOURCE_REGISTERING;
			}

			/* If not first resource, add '.' to separator */
			if(temp_ptr != message_ptr->payload_ptr)
				*temp_ptr++ = ',';

			*temp_ptr++ = '<';
			*temp_ptr++ = '/';
			memcpy(temp_ptr, resource_temp_ptr->path, resource_temp_ptr->pathlen);
			temp_ptr += resource_temp_ptr->pathlen;
			*temp_ptr++ = '>';

			/* Resource attributes */
			if(resource_temp_ptr->resource_parameters_ptr->resource_type_len)
			{
				*temp_ptr++ = ';';
				memcpy(temp_ptr, resource_type_parameter, RT_PARAMETER_LEN);
				temp_ptr += RT_PARAMETER_LEN;
				*temp_ptr++ = '"';
				memcpy(temp_ptr, resource_temp_ptr->resource_parameters_ptr->resource_type_ptr, resource_temp_ptr->resource_parameters_ptr->resource_type_len);
				temp_ptr += resource_temp_ptr->resource_parameters_ptr->resource_type_len;
				*temp_ptr++ = '"';
			}

			if(resource_temp_ptr->resource_parameters_ptr->interface_description_len)
			{
				*temp_ptr++ = ';';
				memcpy(temp_ptr, if_description_parameter, IF_PARAMETER_LEN);
				temp_ptr += IF_PARAMETER_LEN;
				*temp_ptr++ = '"';
				memcpy(temp_ptr, resource_temp_ptr->resource_parameters_ptr->interface_description_ptr, resource_temp_ptr->resource_parameters_ptr->interface_description_len);
				temp_ptr += resource_temp_ptr->resource_parameters_ptr->interface_description_len;
				*temp_ptr++ = '"';
			}

			if(resource_temp_ptr->resource_parameters_ptr->coap_content_type != 0)
			{
				*temp_ptr++ = ';';
				memcpy(temp_ptr, coap_con_type_parameter, COAP_CON_PARAMETER_LEN);
				temp_ptr += COAP_CON_PARAMETER_LEN;
				*temp_ptr++ = '"';
				temp_ptr = sn_nsdl_itoa(temp_ptr, resource_temp_ptr->resource_parameters_ptr->coap_content_type);
				*temp_ptr++ = '"';
			}

			if(resource_temp_ptr->resource_parameters_ptr->observable)
			{
				*temp_ptr++ = ';';
				memcpy(temp_ptr, obs_parameter, OBS_PARAMETER_LEN);
				temp_ptr += OBS_PARAMETER_LEN;
			}

		}

		resource_temp_ptr = sn_grs_get_next_resource();

	}

	return SN_NSDL_SUCCESS;
}

/**
 * \fn static uint16_t sn_nsdl_calculate_registration_body_size(sn_grs_resource_list_s *grs_resources_list_ptr)
 *
 *
 * \brief	Calculates registration message payload size
 *
 * \param	*grs_resources_list_ptr Pointer to list of GRS resources
 *
 * \return	Needed payload size
 */
static uint16_t sn_nsdl_calculate_registration_body_size(uint8_t updating_registeration)
{
	/* Local variables */
	uint16_t return_value = 0;
	sn_nsdl_resource_info_s *resource_temp_ptr;

	/* check pointer */

	resource_temp_ptr = sn_grs_get_first_resource();

	while(resource_temp_ptr)
	{

		if(resource_temp_ptr->resource_parameters_ptr)
		{

			if(updating_registeration && resource_temp_ptr->resource_parameters_ptr->registered == SN_NDSL_RESOURCE_REGISTERED)
			{
				resource_temp_ptr = sn_grs_get_next_resource();
				continue;
			}

			/* If not first resource, then '.' will be added */
			if(return_value)
				return_value++;

			/* Count length for the resource path </path> */
			return_value +=	(3 + resource_temp_ptr->pathlen);

			/* Count lengths of the attributes */

			/* Resource type parameter */
			if(resource_temp_ptr->resource_parameters_ptr->resource_type_len)
			{
				/* ;rt="restype" */
				return_value += (6 + resource_temp_ptr->resource_parameters_ptr->resource_type_len);
			}

			/* Interface description parameter */
			if(resource_temp_ptr->resource_parameters_ptr->interface_description_len)
			{
				/* ;if="iftype" */
				return_value += (6 + resource_temp_ptr->resource_parameters_ptr->interface_description_len);
			}

			if(resource_temp_ptr->resource_parameters_ptr->coap_content_type != 0)
			{
				/* ;if="content" */
				return_value += 6; // all but not content
				return_value += sn_nsdl_itoa_len(resource_temp_ptr->resource_parameters_ptr->coap_content_type);
			}

			if(resource_temp_ptr->resource_parameters_ptr->observable)
			{
				/* ;obs */
				return_value += 4;
			}

		}

		resource_temp_ptr = sn_grs_get_next_resource();

	}

	return return_value;

}

/**
 * \fn static uint8_t sn_nsdl_calculate_uri_query_option_len(sn_nsdl_ep_parameters_s *endpoint_info_ptr, uint8_t msg_type)
 *
 *
 * \brief Calculates needed uri query option length
 *
 * \param *endpoint_info_ptr 	Pointer to endpoint info structure
 * \param msg_type				Message type
 *
 * \return	SN_NSDL_SUCCESS = 0, Failed = -1
 */
static uint8_t sn_nsdl_calculate_uri_query_option_len(sn_nsdl_ep_parameters_s *endpoint_info_ptr, uint8_t msg_type)
{
	uint8_t return_value = 0;
	uint8_t number_of_parameters = 0;


	if((endpoint_info_ptr->endpoint_name_len != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE) && endpoint_info_ptr->endpoint_name_ptr != 0)
	{
		return_value += endpoint_info_ptr->endpoint_name_len;
		return_value += 2;		//h=
		number_of_parameters++;
	}

	if((endpoint_info_ptr->type_len != 0) && (endpoint_info_ptr->type_ptr != 0))
	{
		return_value+=endpoint_info_ptr->type_len;
		return_value += 3;
		number_of_parameters++;
	}

	if((endpoint_info_ptr->contex_len != 0) && (endpoint_info_ptr->contex_ptr != 0))
	{
		return_value+=endpoint_info_ptr->contex_len;
		return_value += 4;
		number_of_parameters++;
	}

	if((endpoint_info_ptr->lifetime_len != 0) && (endpoint_info_ptr->lifetime_ptr != 0))
	{
		return_value+=endpoint_info_ptr->lifetime_len;
		return_value += 3;
		number_of_parameters++;
	}

	if(number_of_parameters != 0)
		return_value += (number_of_parameters - 1);

	return return_value;
}

/**
 * \fn static int8_t sn_nsdl_fill_uri_query_options(sn_nsdl_ep_parameters_s *parameter_ptr, sn_coap_hdr_s *source_msg_ptr, uint8_t msg_type)
 *
 *
 * \brief Fills uri-query options to message header struct
 *
 * \param *parameter_ptr 	Pointer to endpoint parameters struct
 * \param *source_msg_ptr	Pointer to CoAP header struct
 * \param msg_type			Message type
 *
 * \return	SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_fill_uri_query_options(sn_nsdl_ep_parameters_s *parameter_ptr, sn_coap_hdr_s *source_msg_ptr, uint8_t msg_type)
{
	uint8_t *temp_ptr = NULL;
	source_msg_ptr->options_list_ptr->uri_query_len  = sn_nsdl_calculate_uri_query_option_len(parameter_ptr, msg_type);

	if(source_msg_ptr->options_list_ptr->uri_query_len == 0)
		return 0;

	source_msg_ptr->options_list_ptr->uri_query_ptr 	= 	sn_nsdl_alloc(source_msg_ptr->options_list_ptr->uri_query_len);

	if (source_msg_ptr->options_list_ptr->uri_query_ptr == NULL)
			return SN_NSDL_FAILURE;

	temp_ptr = source_msg_ptr->options_list_ptr->uri_query_ptr;

	/******************************************************/
	/* If endpoint name is configured, fill needed fields */
	/******************************************************/

	if((parameter_ptr->endpoint_name_len != 0) && (parameter_ptr->endpoint_name_ptr != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE))
	{
		/* fill endpoint name, first ?h=, then endpoint name */
		memcpy(temp_ptr, ep_name_parameter_string, sizeof(ep_name_parameter_string));
		temp_ptr += EP_NAME_PARAMETERS_LEN;
		memcpy(temp_ptr, parameter_ptr->endpoint_name_ptr, parameter_ptr->endpoint_name_len);
		temp_ptr += parameter_ptr->endpoint_name_len;
	}

	/******************************************************/
	/* If endpoint type is configured, fill needed fields */
	/******************************************************/

	if((parameter_ptr->type_len != 0) && (parameter_ptr->type_ptr != 0))
	{
		if(temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr)
			*temp_ptr++ = '&';

		memcpy(temp_ptr, resource_type_parameter, sizeof(resource_type_parameter));
		temp_ptr += RT_PARAMETER_LEN;
		memcpy(temp_ptr, parameter_ptr->type_ptr, parameter_ptr->type_len);
		temp_ptr += parameter_ptr->type_len;
	}

	/******************************************************/
	/* If Contex is configured, fill needed fields */
	/******************************************************/

	if((parameter_ptr->contex_len != 0) && (parameter_ptr->contex_ptr != 0))
	{
		if(temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr)
			*temp_ptr++ = '&';

		memcpy(temp_ptr, ep_contex_parameter, sizeof(ep_contex_parameter));
		temp_ptr += CON_PARAMETER_LEN;
		memcpy(temp_ptr, parameter_ptr->contex_ptr, parameter_ptr->contex_len);
		temp_ptr += parameter_ptr->contex_len;
	}

	/******************************************************/
	/* If lifetime is configured, fill needed fields */
	/******************************************************/

	if((parameter_ptr->lifetime_len != 0) && (parameter_ptr->lifetime_ptr != 0))
	{
		if(temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr)
			*temp_ptr++ = '&';

		memcpy(temp_ptr, ep_lifetime_parameter, sizeof(ep_lifetime_parameter));
		temp_ptr += LT_PARAMETER_LEN;
		memcpy(temp_ptr, parameter_ptr->lifetime_ptr, parameter_ptr->lifetime_len);
		temp_ptr += parameter_ptr->lifetime_len;
	}

	return SN_NSDL_SUCCESS;
}

/**
 * \fn static uint8_t sn_nsdl_local_rx_function(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr)
 *
 * \brief If received message is reply for the message that NSDL has been sent, it is processed here. Else, packet will be sent to application.
 *
 * \param *coap_packet_ptr	Pointer to received CoAP packet
 * \param *address_ptr		Pointer to source address struct
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_local_rx_function(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr)
{
	int8_t 						status = 0;
	uint16_t					number_of_messages;
	sn_nsdl_sent_messages_s 	*sent_message_temp_ptr;

	/* If we wait for a response to some message.. */
	number_of_messages = sn_linked_list_count_nodes(message_list_ptr);
	if(number_of_messages)
	{
		while(number_of_messages--)
		{
			sent_message_temp_ptr = sn_linked_list_get_last_node(message_list_ptr);

			if(sent_message_temp_ptr->msg_id_number == coap_packet_ptr->msg_id)
			{
				switch(sent_message_temp_ptr->message_type)
				{
				case SN_NSDL_MSG_EVENT:
					break;
				case SN_NSDL_MSG_REGISTER:
					if(coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CREATED)
					{
						sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_IS_REGISTERED;
						sn_nsdl_mark_resources_as_registered();
						status = sn_nsdl_resolve_ep_information(coap_packet_ptr);
						if(status != SN_NSDL_SUCCESS)
						{
							/* Node can be removed */
							sn_nsdl_free(sent_message_temp_ptr);
							sn_linked_list_remove_current_node(message_list_ptr);
							return status;
						}
					}
					break;
				case SN_NSDL_MSG_UNREGISTER:
					if(coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_DELETED)
					{
						if(ep_information_ptr->endpoint_name_ptr)
							{
								sn_nsdl_free(ep_information_ptr->endpoint_name_ptr);
								ep_information_ptr->endpoint_name_ptr = 0;
								ep_information_ptr->endpoint_name_len = 0;
							}

						if(ep_information_ptr->domain_name_ptr)
							{
								sn_nsdl_free(ep_information_ptr->domain_name_ptr);
								ep_information_ptr->domain_name_ptr = 0;
								ep_information_ptr->domain_name_len = 0;
							}

					}
					break;
				case SN_NSDL_MSG_UPDATE:
					break;
				}
				/* Node can be removed */
				sn_nsdl_free(sent_message_temp_ptr);
				sn_linked_list_remove_current_node(message_list_ptr);

				sn_nsdl_rx_callback(coap_packet_ptr, address_ptr);
				return SN_NSDL_SUCCESS;
			}
			sent_message_temp_ptr = sn_linked_list_get_previous_node(message_list_ptr);
		}
	}

	/* No messages to wait for, or message was not response to our request */
	status = sn_nsdl_rx_callback(coap_packet_ptr, address_ptr);

	return status;
}

void sn_nsdl_mark_resources_as_registered(void)
{

	sn_nsdl_resource_info_s *temp_resource;

	temp_resource = sn_grs_get_first_resource();

	while(temp_resource)
	{

		if(temp_resource->resource_parameters_ptr->registered == SN_NDSL_RESOURCE_REGISTERING)
		{

			temp_resource->resource_parameters_ptr->registered = SN_NDSL_RESOURCE_REGISTERED;

		}

		temp_resource = sn_grs_get_next_resource();

	}


}

/**
 * \fn static int8_t sn_nsdl_resolve_ep_information(sn_coap_hdr_s *coap_packet_ptr)
 *
 *
 * \brief Resolves endpoint information from received CoAP message
 *
 * \param *coap_packet_ptr Pointer to received CoAP message
 *
 * \return	SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_resolve_ep_information(sn_coap_hdr_s *coap_packet_ptr)
{
	uint8_t		*temp_ptr;
	uint8_t		parameter_count 	= 0;
	uint16_t	parameter_len 		= 0;
	uint8_t		end_found = 0;

	if(!coap_packet_ptr)
		return SN_NSDL_FAILURE;
	if(!coap_packet_ptr->options_list_ptr)
		return SN_NSDL_FAILURE;
	if(!coap_packet_ptr->options_list_ptr->location_path_ptr)
		return SN_NSDL_FAILURE;

	//i = coap_packet_ptr->options_list_ptr->location_path_len;
	temp_ptr = coap_packet_ptr->options_list_ptr->location_path_ptr;

	while(temp_ptr <= (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len))
	{

		if(temp_ptr == (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len))
		{
			end_found = 1;
		}
		else if(*temp_ptr == 0)
		{
			end_found = 1;
		}

		if(end_found)
		{

			end_found = 0;

			parameter_count++;
			if(parameter_count == 2)
			{
				if(!ep_information_ptr->domain_name_ptr)
				{
					ep_information_ptr->domain_name_len = parameter_len - 1;
					ep_information_ptr->domain_name_ptr = sn_nsdl_alloc(ep_information_ptr->domain_name_len);
					if(!ep_information_ptr->domain_name_ptr)
						return SN_NSDL_FAILURE;
					memcpy(ep_information_ptr->domain_name_ptr, temp_ptr - ep_information_ptr->domain_name_len, ep_information_ptr->domain_name_len);
				}
			}
			if(parameter_count == 3)
			{
				if(!ep_information_ptr->endpoint_name_ptr)
				{
					ep_information_ptr->endpoint_name_len = parameter_len - 1;
					ep_information_ptr->endpoint_name_ptr = sn_nsdl_alloc(ep_information_ptr->endpoint_name_len);
					if(!ep_information_ptr->endpoint_name_ptr)
					{
						if(ep_information_ptr->domain_name_ptr)
						{
							sn_nsdl_free(ep_information_ptr->domain_name_ptr);
							ep_information_ptr->domain_name_ptr = NULL;
							ep_information_ptr->domain_name_len = 0;
						}

						return SN_NSDL_FAILURE;

					}
					memcpy(ep_information_ptr->endpoint_name_ptr, temp_ptr - ep_information_ptr->endpoint_name_len, ep_information_ptr->endpoint_name_len);
				}
			}
			parameter_len = 0;
		}
		parameter_len++;
		temp_ptr++;
	}


	return SN_NSDL_SUCCESS;
}

/*
 * \brief This function is used to set the NSP address given by an application.
 * @return 0 on success, -1 on false to indicate that NSDL internal address pointer is not allocated (call nsdl_init() first).
 */
int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port)
{
	if(nsp_address_ptr && NSP_address)
	{
		if(nsp_address_ptr->addr_ptr)
		{
			memcpy(nsp_address_ptr->addr_ptr, NSP_address, 16);
			nsp_address_ptr->port = port;
			return 0;
		}
	}
	return -1;
}


static uint8_t sn_nsdl_itoa_len(uint8_t value)
{
	uint8_t i = 0;

	do
	{
		i++;
	}while((value /= 10) > 0);

	return i;
}

static uint8_t *sn_nsdl_itoa(uint8_t *ptr, uint8_t value)
{

	uint8_t start = 0;
	uint8_t end = 0;
	uint8_t i;

	i = 0;

	/* ITOA */
	do
	{
		ptr[i++] = (value % 10) + '0';
	}while((value /= 10) > 0);

	end = i - 1;

	/* reverse (part of ITOA) */
	while(start < end)
	{
		uint8_t chr;

		chr = ptr[start];
		ptr[start] = ptr[end];
		ptr[end] = chr;

		start++;
		end--;

	}
	return (ptr + i);
}
