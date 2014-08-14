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

/* Defines */
#define RESOURCE_DIR_LEN				2
#define RESOURCE_DIR_PATH				{'r','d'}

/* * Endpoint parameter defines * */

/* Endpoint name. A unique name for the registering node in a domain.  */
#define EP_NAME_PARAMETERS_LEN			3
#define EP_NAME_PARAMETERS				{'e','p','='}

/* Endpoint type */
#define ET_PARAMETER_LEN			3
#define ET_PARAMETER				{'e','t','='}

/* Lifetime. Number of seconds that this registration will be valid for. Must be updated within this time, or will be removed. */
#define LT_PARAMETER_LEN				3
#define LT_PARAMETER					{'l','t','='}

/* Domain name. If this parameter is missing, a default domain is assumed. */
#define DOMAIN_PARAMETER_LEN			2
#define DOMAIN_PARAMETER				{'d','='}

/* * Resource parameters * */

/* Resource type. Only once for registration */
#define RT_PARAMETER_LEN				3
#define RT_PARAMETER					{'r','t','='}

/* Interface description. Only once */
#define IF_PARAMETER_LEN				3
#define IF_PARAMETER					{'i','f','='}

/* Observable */
#define OBS_PARAMETER_LEN				3
#define OBS_PARAMETER					{'o','b','s'}

/* Auto-observable */
#define AOBS_PARAMETER_LEN				8
#define AOBS_PARAMETER					{'a','o','b','s',';','i','d','='}

/* CoAP content type */
#define COAP_CON_PARAMETER_LEN			3
#define COAP_CON_PARAMETER				{'c','t','='}

/* * OMA BS parameters * */

#define BS_PATH							{'b','s'}

#define BS_EP_PARAMETER_LEN				3
#define BS_EP_PARAMETER					{'e','p','='}


#define SN_NSDL_EP_REGISTER_MESSAGE		1
#define SN_NSDL_EP_UPDATE_MESSAGE		2

#define	SN_NSDL_MSG_NO_TYPE				0
#define	SN_NSDL_MSG_REGISTER			1
#define SN_NSDL_MSG_UNREGISTER			2
#define SN_NSDL_MSG_UPDATE				3
#define SN_NSDL_MSG_EVENT				4

#define	SN_NSDL_MAX_MESSAGE_COUNT		1

/* Constants */
SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t 	ep_name_parameter_string[] 	= EP_NAME_PARAMETERS;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		resource_path_ptr[]			= RESOURCE_DIR_PATH;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		resource_type_parameter[]	= RT_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		obs_parameter[]				= OBS_PARAMETER;

//SN_NSDL_CONST_MEMORY_ATTRIBUTE
//static uint8_t		aobs_parameter[]			= AOBS_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		if_description_parameter[]	= IF_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		ep_lifetime_parameter[]		= LT_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t		ep_domain_parameter[]		= DOMAIN_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t 	coap_con_type_parameter[]	= COAP_CON_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t bs_uri[] 					= BS_PATH;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t bs_ep_name[] 					= BS_EP_PARAMETER;

SN_NSDL_CONST_MEMORY_ATTRIBUTE
static uint8_t et_parameter[] 					= ET_PARAMETER;


/* Global function pointers */
static void 	*(*sn_nsdl_alloc)(uint16_t)  = 0;
static void 	(*sn_nsdl_free)(void*) = 0;
static uint8_t 	(*sn_nsdl_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *) = 0;
static uint8_t 	(*sn_nsdl_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *) = 0;
/* Global variables */
static sn_nsdl_ep_parameters_s		*ep_information_ptr  = 0; 	// Endpoint parameters, Name, Domain etc..
static sn_nsdl_oma_server_info_t	*nsp_address_ptr = 0;		// NSP server address information
static NS_LIST_DEFINE(				message_list, sn_nsdl_sent_messages_s, link);
static uint16_t						message_count;
static uint8_t 						sn_nsdl_endpoint_registered = 0;

/* OMA bootstrap server address information */
static uint8_t 						*oma_bs_address_ptr 	= 0; 												/* Bootstrap address pointer */
static uint8_t						oma_bs_address_len 		= 0; 												/* Bootstrap address length */
static uint16_t						oma_bs_port 			= 0; 												/* Bootstrap port */
static void 						(*sn_nsdl_oma_bs_done_cb)(sn_nsdl_oma_server_info_t *server_info_ptr) = 0;	/* Callback to inform application when bootstrap is done */

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
static uint32_t 		sn_nsdl_atoi								(uint8_t *ptr, uint8_t len);
static uint32_t 		sn_nsdl_ahextoi								(uint8_t *ptr, uint8_t len);
static int8_t			sn_nsdl_resolve_lwm2m_address				(uint8_t *uri, uint16_t uri_len);
static int8_t 			sn_nsdl_process_oma_tlv						(uint8_t *data_ptr, uint16_t data_len);
static void 			sn_nsdl_check_oma_bs_status					(void);


int8_t sn_nsdl_destroy(void)
{
	ns_list_foreach_safe(sn_nsdl_sent_messages_s, tmp, &message_list)
	{
		ns_list_remove(&message_list, tmp);
		sn_nsdl_free(tmp);
		tmp = 0;
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
		if(nsp_address_ptr->omalw_address_ptr)
		{
			if(nsp_address_ptr->omalw_address_ptr->addr_ptr)
			{
				sn_nsdl_free(nsp_address_ptr->omalw_address_ptr->addr_ptr);
				nsp_address_ptr->omalw_address_ptr->addr_ptr = 0;
			}
			sn_nsdl_free(nsp_address_ptr->omalw_address_ptr);
		}

		sn_nsdl_free(nsp_address_ptr);
		nsp_address_ptr = 0;
	}

	/* Destroy also libCoap and grs part of libNsdl */
	sn_grs_destroy();
	sn_coap_protocol_destroy();

	return 0;
}

int8_t sn_nsdl_init	(uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
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

	/* Initialize ep parameters struct */
	if(!ep_information_ptr)
	{
		ep_information_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_ep_parameters_s));
		if(!ep_information_ptr)
		{
			return SN_NSDL_FAILURE;
		}
		memset(ep_information_ptr, 0, sizeof(sn_nsdl_ep_parameters_s));
	}

	/* Initialize GRS */
	if(sn_grs_init(sn_nsdl_tx_cb,&sn_nsdl_local_rx_function, sn_memory))
	{

		sn_nsdl_free(ep_information_ptr);
		ep_information_ptr = 0;
		return SN_NSDL_FAILURE;

	}

	sn_nsdl_resolve_nsp_address();

	sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;

	return SN_NSDL_SUCCESS;
}

int8_t sn_nsdl_GET_with_QUERY(char * uri, uint16_t urilen, uint8_t*destination, uint16_t port, char *query, uint8_t query_len)
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

	sn_grs_send_coap_message(dst, message_ptr);

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

int8_t sn_nsdl_GET(char * uri, uint16_t urilen, uint8_t*destination, uint16_t port)
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
	sn_grs_send_coap_message(dst, message_ptr);

	if(dst->addr_ptr)
		sn_nsdl_free(dst->addr_ptr);
	if(dst)
		sn_nsdl_free(dst);
	message_ptr->uri_path_ptr = NULL;
	message_ptr->options_list_ptr->uri_host_ptr = NULL;

	sn_coap_parser_release_allocated_coap_msg_mem(message_ptr);
	return SN_NSDL_SUCCESS;
}



int8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr)
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
	status = sn_nsdl_internal_coap_send(register_message_ptr, nsp_address_ptr->omalw_address_ptr, SN_NSDL_MSG_REGISTER);

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

int8_t sn_nsdl_unregister_endpoint(void)
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
		sn_nsdl_internal_coap_send(unregister_message_ptr, nsp_address_ptr->omalw_address_ptr, SN_NSDL_MSG_UNREGISTER);

		/* Free memory */
		sn_coap_parser_release_allocated_coap_msg_mem(unregister_message_ptr);

	}

	return SN_NSDL_SUCCESS;
}

int8_t sn_nsdl_update_registration (sn_nsdl_ep_parameters_s *endpoint_info_ptr)
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
	sn_nsdl_internal_coap_send(register_message_ptr, nsp_address_ptr->omalw_address_ptr, SN_NSDL_MSG_UPDATE);

	if(register_message_ptr->payload_ptr)
		sn_nsdl_free(register_message_ptr->payload_ptr);
	sn_coap_parser_release_allocated_coap_msg_mem(register_message_ptr);

	return SN_NSDL_SUCCESS;
}

void sn_nsdl_nsp_lost(void)
{
	sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;
	return;
}

int8_t sn_nsdl_is_ep_registered(void)
{
	return sn_nsdl_endpoint_registered;
}

uint16_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
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
	if(sn_grs_send_coap_message(nsp_address_ptr->omalw_address_ptr, notification_message_ptr) == SN_NSDL_FAILURE)
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

/* * * * * * * * * * */
/* ~ OMA functions ~ */
/* * * * * * * * * * */

int8_t sn_nsdl_oma_bootstrap(sn_nsdl_addr_s *bootstrap_address_ptr, sn_nsdl_bs_ep_info_t *bootstrap_endpoint_info_ptr, void (*oma_bs_status_cb)(sn_nsdl_oma_server_info_t *server_info_ptr))
{

	/* Local variables */
	sn_coap_hdr_s bootstrap_coap_header;
	uint8_t *uri_query_tmp_ptr;

	/* Check parameters */
	if(!bootstrap_address_ptr || !bootstrap_endpoint_info_ptr || !oma_bs_status_cb)
		return SN_NSDL_FAILURE;

	sn_nsdl_oma_bs_done_cb = oma_bs_status_cb;

	/* Init CoAP header struct */
	memset(&bootstrap_coap_header, 0, sizeof(sn_coap_hdr_s));

	bootstrap_coap_header.options_list_ptr = sn_nsdl_alloc(sizeof(sn_coap_options_list_s));
	if(!bootstrap_coap_header.options_list_ptr)
		return SN_NSDL_FAILURE;

	memset(bootstrap_coap_header.options_list_ptr, 0, sizeof(sn_coap_options_list_s));

	/* Build bootstrap start message */
	bootstrap_coap_header.msg_code = COAP_MSG_CODE_REQUEST_POST;
	bootstrap_coap_header.msg_type = COAP_MSG_TYPE_CONFIRMABLE;

	bootstrap_coap_header.uri_path_ptr = bs_uri;
	bootstrap_coap_header.uri_path_len = sizeof(bs_uri);

	uri_query_tmp_ptr = sn_nsdl_alloc(bootstrap_endpoint_info_ptr->endpoint_name_len + BS_EP_PARAMETER_LEN);
	if(!uri_query_tmp_ptr)
	{
		sn_nsdl_free(bootstrap_coap_header.options_list_ptr);
		return SN_NSDL_FAILURE;
	}

	memcpy(uri_query_tmp_ptr, bs_ep_name, BS_EP_PARAMETER_LEN);
	memcpy((uri_query_tmp_ptr + BS_EP_PARAMETER_LEN), bootstrap_endpoint_info_ptr->endpoint_name_ptr, bootstrap_endpoint_info_ptr->endpoint_name_len);

	bootstrap_coap_header.options_list_ptr->uri_query_len = bootstrap_endpoint_info_ptr->endpoint_name_len + BS_EP_PARAMETER_LEN;
	bootstrap_coap_header.options_list_ptr->uri_query_ptr = uri_query_tmp_ptr;

	/* Save bootstrap server address */
	oma_bs_address_len = bootstrap_address_ptr->addr_len; 		/* Length.. */
	oma_bs_address_ptr = sn_nsdl_alloc(oma_bs_address_len);		/* Address.. */
	if(!oma_bs_address_ptr)
	{
		sn_nsdl_free(bootstrap_coap_header.options_list_ptr);
		sn_nsdl_free(uri_query_tmp_ptr);
		return SN_NSDL_FAILURE;
	}
	memcpy(oma_bs_address_ptr, bootstrap_address_ptr->addr_ptr, oma_bs_address_len);
	oma_bs_port = bootstrap_address_ptr->port;					/* And port */

	/* Send message */
	sn_nsdl_send_coap_message(bootstrap_address_ptr, &bootstrap_coap_header);

	/* Free allocated memory */
	sn_nsdl_free(uri_query_tmp_ptr);
	sn_nsdl_free(bootstrap_coap_header.options_list_ptr);

	return SN_NSDL_SUCCESS;
}

omalw_certificate_list_t *sn_nsdl_get_certificates(uint8_t certificate_chain)
{
		sn_nsdl_resource_info_s *resource_ptr = 0;;
		omalw_certificate_list_t *certi_list_ptr = 0;

		certi_list_ptr = sn_nsdl_alloc(sizeof(omalw_certificate_list_t));

		if(!certi_list_ptr)
			return NULL;

		/* Get private key resource */
		resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/5");
		if(!resource_ptr)
		{
			sn_nsdl_free(certi_list_ptr);
			return NULL;
		}
		certi_list_ptr->own_private_key_ptr = resource_ptr->resource;
		certi_list_ptr->own_private_key_len = resource_ptr->resourcelen;

		/* Get client certificate resource */
		resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/4");
		if(!resource_ptr)
		{
			sn_nsdl_free(certi_list_ptr);
			return NULL;
		}
		certi_list_ptr->certificate_ptr[0] = resource_ptr->resource;
		certi_list_ptr->certificate_len[0] = resource_ptr->resourcelen;

		/* Get root certificate resource */
		resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/3");
		if(!resource_ptr)
		{
			sn_nsdl_free(certi_list_ptr);
			return NULL;
		}
		certi_list_ptr->certificate_ptr[1] = resource_ptr->resource;
		certi_list_ptr->certificate_len[1] = resource_ptr->resourcelen;

		/* return filled list */
		return certi_list_ptr;

}

int8_t sn_nsdl_set_certificates(omalw_certificate_list_t* certificate_ptr, uint8_t certificate_chain)
{
	/* Check pointers */
	if(!certificate_ptr)
		return SN_NSDL_FAILURE;

	sn_nsdl_resource_info_s *resource_ptr = 0;;


	/* Get private key resource */
	resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/5");
	if(!resource_ptr)
	{
		return SN_NSDL_FAILURE;
	}
	resource_ptr->resource = certificate_ptr->own_private_key_ptr;
	resource_ptr->resourcelen = certificate_ptr->own_private_key_len;

	/* Get client certificate resource */
	resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/4");
	if(!resource_ptr)
	{
		return SN_NSDL_FAILURE;
	}
	resource_ptr->resource = certificate_ptr->certificate_ptr[0];
	resource_ptr->resourcelen = certificate_ptr->certificate_len[0];

	/* Get root certificate resource */
	resource_ptr = sn_nsdl_get_resource(5, (void*)"0/0/3");
	if(!resource_ptr)
	{
		return SN_NSDL_FAILURE;
	}
	resource_ptr->resource = certificate_ptr->certificate_ptr[1];
	resource_ptr->resourcelen = certificate_ptr->certificate_len[1];

	return SN_NSDL_SUCCESS;
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


int8_t sn_nsdl_process_coap(uint8_t *packet_ptr, uint16_t packet_len, sn_nsdl_addr_s *src_ptr)
{
	sn_coap_hdr_s 			*coap_packet_ptr 	= NULL;
	sn_coap_hdr_s			*coap_response_ptr  = NULL;

	/* Parse CoAP packet */
	coap_packet_ptr = sn_coap_protocol_parse(src_ptr, packet_len, packet_ptr);

	/* Check if parsing was successfull */
	if(coap_packet_ptr == (sn_coap_hdr_s *)NULL)
		return SN_NSDL_FAILURE;

	/* Check, if coap itself sends response, or block receiving is ongoing... */
	if(coap_packet_ptr->coap_status != COAP_STATUS_OK && coap_packet_ptr->coap_status != COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED)
	{
		sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
		return SN_NSDL_SUCCESS;
	}

	/* If proxy options added, return not supported */
	if (coap_packet_ptr->options_list_ptr)
	{
		if(coap_packet_ptr->options_list_ptr->proxy_uri_len)
		{
			coap_response_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED);
			if(coap_response_ptr)
			{
				sn_nsdl_send_coap_message(src_ptr, coap_response_ptr);
				sn_coap_parser_release_allocated_coap_msg_mem(coap_response_ptr);
				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				return SN_NSDL_SUCCESS;
			}
			else
			{
				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				return SN_NSDL_FAILURE;
			}
		}
	}


	/* * If OMA bootstrap message... * */
	if((oma_bs_address_len == src_ptr->addr_len) && (oma_bs_port == src_ptr->port) && !memcmp(oma_bs_address_ptr, src_ptr->addr_ptr, oma_bs_address_len))
	{
		/* TLV message. Parse message and check status of the OMA bootstrap  */
		/* process.	If ok, call cb function and return. Otherwise send error */
		/* and return failure.												 */

		if(coap_packet_ptr->content_type_len == 1) //todo check message type
		{
			if(*coap_packet_ptr->content_type_ptr == 99)
			{
				/* TLV parsing failed. Send response to get non-tlv messages */
				if(sn_nsdl_process_oma_tlv(coap_packet_ptr->payload_ptr, coap_packet_ptr->payload_len) == SN_NSDL_FAILURE)
				{
					coap_response_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE);
					if(coap_response_ptr)
					{
						sn_nsdl_send_coap_message(src_ptr, coap_response_ptr);
						sn_coap_parser_release_allocated_coap_msg_mem(coap_response_ptr);
						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
					}
					else
					{
						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
						return SN_NSDL_FAILURE;
					}
				}
				/* Success TLV parsing */
				else
				{
					coap_response_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CREATED);
					if(coap_response_ptr)
					{
						sn_nsdl_send_coap_message(src_ptr, coap_response_ptr);
						sn_coap_parser_release_allocated_coap_msg_mem(coap_response_ptr);
						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
					}
					else
					{
						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
						return SN_NSDL_FAILURE;
					}
					sn_nsdl_check_oma_bs_status();
				}

				return SN_NSDL_SUCCESS;
			}

			/* Non - TLV message */
			else if(*coap_packet_ptr->content_type_ptr == 97)
			{
				sn_grs_process_coap(coap_packet_ptr, src_ptr);

				/* Todo: move this copying to sn_nsdl_check_oma_bs_status(), also from TLV parser */
				/* Security mode */
				if(*(coap_packet_ptr->uri_path_ptr + (coap_packet_ptr->uri_path_len - 1)) == '2')
				{
					nsp_address_ptr->omalw_server_security = (omalw_server_security_t)sn_nsdl_atoi(coap_packet_ptr->payload_ptr, coap_packet_ptr->payload_len);
					sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				}

				/* NSP address */
				else if (*(coap_packet_ptr->uri_path_ptr + (coap_packet_ptr->uri_path_len - 1)) == '0')
				{
					sn_nsdl_resolve_lwm2m_address(coap_packet_ptr->payload_ptr, coap_packet_ptr->payload_len);
					sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				}

				sn_nsdl_check_oma_bs_status();
			}
		}

		return SN_NSDL_SUCCESS;
	}



	/* * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* If message is response message, call RX callback  */
	/* * * * * * * * * * * * * * * * * * * * * * * * * * */

	if((coap_packet_ptr->msg_code > COAP_MSG_CODE_REQUEST_DELETE) || (coap_packet_ptr->msg_type == COAP_MSG_TYPE_ACKNOWLEDGEMENT))
	{
		int8_t retval = sn_nsdl_local_rx_function(coap_packet_ptr, src_ptr);
		if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
		{
			sn_nsdl_free(coap_packet_ptr->payload_ptr);
			coap_packet_ptr->payload_ptr = 0;
		}
		sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
		return retval;
	}

	/* * * * * * * * * * * * * * * */
	/* Other messages are for GRS  */
	/* * * * * * * * * * * * * * * */

	return sn_grs_process_coap(coap_packet_ptr, src_ptr);
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

sn_nsdl_resource_info_s *sn_nsdl_get_resource(uint16_t pathlen, uint8_t *path_ptr)
{
	return sn_grs_get_resource(pathlen, path_ptr);
}

sn_grs_resource_list_s *sn_nsdl_list_resource(uint16_t pathlen, uint8_t *path_ptr)
{
	return sn_grs_list_resource(pathlen, path_ptr);
}

void sn_nsdl_free_resource_list(sn_grs_resource_list_s *list)
{
	sn_grs_free_resource_list(list);
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
			if(message_count >= SN_NSDL_MAX_MESSAGE_COUNT)
			{
				sn_nsdl_sent_messages_s *message_temp_ptr = ns_list_get_first(&message_list);
				ns_list_remove(&message_list, message_temp_ptr);
				--message_count;
				sn_nsdl_free(message_temp_ptr);
			}

			message_ptr->message_type = message_description;
			message_ptr->msg_id_number = coap_header_ptr->msg_id;
			ns_list_add_to_end(&message_list, message_ptr);
			++message_count;

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
 * \note Application must set NSP address with set_nsp_address
 */
static void sn_nsdl_resolve_nsp_address(void)
{
	/* Local variables */
	if(!nsp_address_ptr)
	{
		//allocate only if previously not allocated
		nsp_address_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_oma_server_info_t));
	}

	if(nsp_address_ptr)
	{
		nsp_address_ptr->omalw_server_security = SEC_NOT_SET;
		/* This is only for version 0.5 */
		nsp_address_ptr->omalw_address_ptr = sn_nsdl_alloc(sizeof(sn_nsdl_addr_s));
		if(nsp_address_ptr->omalw_address_ptr)
		{
			memset(nsp_address_ptr->omalw_address_ptr, 0, sizeof(sn_nsdl_addr_s));
			nsp_address_ptr->omalw_address_ptr->type = SN_NSDL_ADDRESS_TYPE_NONE;
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
	const sn_nsdl_resource_info_s 	*resource_temp_ptr;


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

			/* ;obs */
			if(resource_temp_ptr->resource_parameters_ptr->observable)
			{
				*temp_ptr++ = ';';
				memcpy(temp_ptr, obs_parameter, OBS_PARAMETER_LEN);
				temp_ptr += OBS_PARAMETER_LEN;
			}

			/* ;aobs;id= */
			/* todo: aosb not supported ATM - needs fixing */
			/*
			if((resource_temp_ptr->resource_parameters_ptr->auto_obs_len > 0 && resource_temp_ptr->resource_parameters_ptr->auto_obs_len <= 8) &&
					resource_temp_ptr->resource_parameters_ptr->auto_obs_ptr)
			{
				uint8_t i = 0;

				*temp_ptr++ = ';';
				memcpy(temp_ptr, aobs_parameter, AOBS_PARAMETER_LEN);
				temp_ptr += AOBS_PARAMETER_LEN;

				while(i < resource_temp_ptr->resource_parameters_ptr->auto_obs_len)
				{
					temp_ptr = sn_nsdl_itoa(temp_ptr, *(resource_temp_ptr->resource_parameters_ptr->auto_obs_ptr + i));
					i++;
				}
			}
			*/

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
	const sn_nsdl_resource_info_s *resource_temp_ptr;

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
			/*todo: aobs not supported ATM - needs fixing*/
			/*
			if((resource_temp_ptr->resource_parameters_ptr->auto_obs_len > 0 && resource_temp_ptr->resource_parameters_ptr->auto_obs_len <= 8) &&
					resource_temp_ptr->resource_parameters_ptr->auto_obs_ptr)
			{
				uint8_t i = resource_temp_ptr->resource_parameters_ptr->auto_obs_len;
				// ;aobs;id=
				return_value += 9;
				while(i--)
				{
					return_value += sn_nsdl_itoa_len(*(resource_temp_ptr->resource_parameters_ptr->auto_obs_ptr + i));
				}
			}
			*/

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
		return_value += EP_NAME_PARAMETERS_LEN;	//ep=
		number_of_parameters++;
	}

	if((endpoint_info_ptr->type_len != 0) && (endpoint_info_ptr->type_ptr != 0))
	{
		return_value+=endpoint_info_ptr->type_len;
		return_value += ET_PARAMETER_LEN; 		//et=
		number_of_parameters++;
	}

	if((endpoint_info_ptr->lifetime_len != 0) && (endpoint_info_ptr->lifetime_ptr != 0))
	{
		return_value+=endpoint_info_ptr->lifetime_len;
		return_value += LT_PARAMETER_LEN;		//lt=
		number_of_parameters++;
	}

	if((endpoint_info_ptr->domain_name_len != 0) && (endpoint_info_ptr->domain_name_ptr != 0))
	{
		return_value+=endpoint_info_ptr->domain_name_len;
		return_value += DOMAIN_PARAMETER_LEN;		//d=
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
		/* fill endpoint name, first ?ep=, then endpoint name */
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

		memcpy(temp_ptr, et_parameter, sizeof(et_parameter));
		temp_ptr += ET_PARAMETER_LEN;
		memcpy(temp_ptr, parameter_ptr->type_ptr, parameter_ptr->type_len);
		temp_ptr += parameter_ptr->type_len;
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

	/******************************************************/
	/* If domain is configured, fill needed fields */
	/******************************************************/

	if((parameter_ptr->domain_name_len != 0) && (parameter_ptr->domain_name_ptr != 0))
	{
		if(temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr)
			*temp_ptr++ = '&';

		memcpy(temp_ptr, ep_domain_parameter, sizeof(ep_domain_parameter));
		temp_ptr += DOMAIN_PARAMETER_LEN;
		memcpy(temp_ptr, parameter_ptr->domain_name_ptr, parameter_ptr->domain_name_len);
		temp_ptr += parameter_ptr->domain_name_len;
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

	if((coap_packet_ptr == 0) || (address_ptr == 0))
		return -1;

	/* If we wait for a response to some message.. */
	ns_list_foreach(sn_nsdl_sent_messages_s, sent_message_temp_ptr, &message_list)
	{
		if(sent_message_temp_ptr->msg_id_number == coap_packet_ptr->msg_id)
		{
			switch(sent_message_temp_ptr->message_type)
			{
			case SN_NSDL_MSG_REGISTER:
				if(coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CREATED)
				{
					sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_IS_REGISTERED;
					sn_nsdl_mark_resources_as_registered();
					status = sn_nsdl_resolve_ep_information(coap_packet_ptr);
					if(status != SN_NSDL_SUCCESS)
					{
						/* Node can be removed */
						ns_list_remove(&message_list, sent_message_temp_ptr);
						--message_count;
						sn_nsdl_free(sent_message_temp_ptr);
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
			case SN_NSDL_MSG_EVENT:
			case SN_NSDL_MSG_UPDATE:
				break;
			}
			/* Node can be removed */
			ns_list_remove(&message_list, sent_message_temp_ptr);
			--message_count;
			sn_nsdl_free(sent_message_temp_ptr);

			sn_nsdl_rx_callback(coap_packet_ptr, address_ptr);
			return SN_NSDL_SUCCESS;
		}
	}

	/* No messages to wait for, or message was not response to our request */
	status = sn_nsdl_rx_callback(coap_packet_ptr, address_ptr);

	return status;
}

void sn_nsdl_mark_resources_as_registered(void)
{

	const sn_nsdl_resource_info_s *temp_resource;

	temp_resource = sn_grs_get_first_resource();

	while(temp_resource)
	{
		if(temp_resource->resource_parameters_ptr)
		{
			if(temp_resource->resource_parameters_ptr->registered == SN_NDSL_RESOURCE_REGISTERING)
			{
				temp_resource->resource_parameters_ptr->registered = SN_NDSL_RESOURCE_REGISTERED;
			}
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

	if(!coap_packet_ptr)
		return SN_NSDL_FAILURE;
	if(!coap_packet_ptr->options_list_ptr)
		return SN_NSDL_FAILURE;
	if(!coap_packet_ptr->options_list_ptr->location_path_ptr)
		return SN_NSDL_FAILURE;

	temp_ptr = coap_packet_ptr->options_list_ptr->location_path_ptr;

	while(temp_ptr <= (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len))
	{

		if((temp_ptr == (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len)) || (*temp_ptr == '/'))
		{

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

/**
 * \fn int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port, sn_nsdl_addr_type_e address_type)
 * \brief This function is used to set the NSP address given by an application.
 * \param uint8_t *NSP_address Pointer to NSP address Note! IPv6 address must always be 16 bytes long and IPv4 address must always be 4 bytes long!
 * \param uint16_t port NSP port
 * \param sn_nsdl_addr_type_e address_type NSP address type (SN_NSDL_ADDRESS_TYPE_IPV6 or SN_NSDL_ADDRESS_TYPE_IPV4)
 * \return 0 on success, -1 on false to indicate that NSDL internal address pointer is not allocated (call nsdl_init() first).
 *
 */
int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port, sn_nsdl_addr_type_e address_type)
{

	/* Check parameters and source pointers */
	if(!nsp_address_ptr || !NSP_address)
	{
		return -1;
	}

	nsp_address_ptr->omalw_address_ptr->type = address_type;
	nsp_address_ptr->omalw_server_security = SEC_NOT_SET;

	if(address_type == SN_NSDL_ADDRESS_TYPE_IPV4)
	{
		if(nsp_address_ptr->omalw_address_ptr->addr_ptr)
		{
			sn_nsdl_free(nsp_address_ptr->omalw_address_ptr->addr_ptr);
		}

		nsp_address_ptr->omalw_address_ptr->addr_len = 4;

		nsp_address_ptr->omalw_address_ptr->addr_ptr = sn_nsdl_alloc(nsp_address_ptr->omalw_address_ptr->addr_len);
		if(!nsp_address_ptr->omalw_address_ptr->addr_ptr)
			return -1;

		memcpy(nsp_address_ptr->omalw_address_ptr->addr_ptr, NSP_address, nsp_address_ptr->omalw_address_ptr->addr_len);
		nsp_address_ptr->omalw_address_ptr->port = port;
	}

	else if(address_type == SN_NSDL_ADDRESS_TYPE_IPV6)
	{
		if(nsp_address_ptr->omalw_address_ptr->addr_ptr)
		{
			sn_nsdl_free(nsp_address_ptr->omalw_address_ptr->addr_ptr);
		}

		nsp_address_ptr->omalw_address_ptr->addr_len = 16;

		nsp_address_ptr->omalw_address_ptr->addr_ptr = sn_nsdl_alloc(nsp_address_ptr->omalw_address_ptr->addr_len);
		if(!nsp_address_ptr->omalw_address_ptr->addr_ptr)
			return -1;

		memcpy(nsp_address_ptr->omalw_address_ptr->addr_ptr, NSP_address, nsp_address_ptr->omalw_address_ptr->addr_len);
		nsp_address_ptr->omalw_address_ptr->port = port;
	}
	return 0;
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

static uint32_t sn_nsdl_atoi(uint8_t *ptr, uint8_t len)
{

	uint32_t result = 0;

	while(len--)
	{

		if(result)
		{
			result *= 10;
		}

		if(*ptr >= '0' && *ptr<= '9')
			result += *ptr - '0';
		else if(*ptr >= 'a' && *ptr <= 'f')
			result += *ptr - 87;
		else if(*ptr >= 'A' && *ptr <= 'F')
			result += *ptr - 55;

		ptr++;

	}
	return result;

}

static uint32_t sn_nsdl_ahextoi(uint8_t *ptr, uint8_t len)
{

	uint32_t result = 0;

	while(len--)
	{

		if(result)
		{
			result *= 16;
		}

		if(*ptr >= '0' && *ptr<= '9')
			result += *ptr - '0';
		else if(*ptr >= 'a' && *ptr <= 'f')
			result += *ptr - 87;
		else if(*ptr >= 'A' && *ptr <= 'F')
			result += *ptr - 55;

		ptr++;

	}
	return result;

}

static int8_t sn_nsdl_resolve_lwm2m_address(uint8_t *uri, uint16_t uri_len)
{
	uint8_t *temp_ptr = uri;
	uint8_t i = 0;
	uint8_t char_cnt = 0;

	/* jump over coap// */
	while((*(temp_ptr - 2) != '/') || (*(temp_ptr - 1) != '/'))
	{
		temp_ptr++;
		if(temp_ptr - uri >= uri_len)
			return SN_NSDL_FAILURE;
	}

	/* Resolve address type */
	/* Count semicolons */

	while(i < (uri_len - (temp_ptr - uri)))
	{
		if(*(temp_ptr + i) == ':')
			char_cnt++;
		i++;
	}

	/* IPv6 */
	if(char_cnt > 2)
	{
		i = 0;

		nsp_address_ptr->omalw_address_ptr->type = SN_NSDL_ADDRESS_TYPE_IPV6;
		nsp_address_ptr->omalw_address_ptr->addr_len = 16;
		nsp_address_ptr->omalw_address_ptr->addr_ptr = sn_nsdl_alloc(16);
		if(!nsp_address_ptr->omalw_address_ptr->addr_ptr)
			return SN_NSDL_FAILURE;

		memset(nsp_address_ptr->omalw_address_ptr->addr_ptr, 0, 16);
		/* If not found, return failure */
		if(*temp_ptr == '[')
			temp_ptr++;

		/* Resolve address */
		while(i < 16 && ((temp_ptr - uri) + char_cnt) < uri_len)
		{
			char_cnt = 0;
			while(*(temp_ptr + char_cnt) != ':' && *(temp_ptr + char_cnt) != ']')
			{
				char_cnt++;
			}

			if(char_cnt <= 2)
				i++;

			while(char_cnt)
			{
				if(char_cnt%2)
				{
					*(nsp_address_ptr->omalw_address_ptr->addr_ptr + i) = (uint8_t)sn_nsdl_ahextoi(temp_ptr, 1);
					temp_ptr++;
					char_cnt --;
				}
				else
				{
					*(nsp_address_ptr->omalw_address_ptr->addr_ptr + i) = (uint8_t)sn_nsdl_ahextoi(temp_ptr, 2);
					temp_ptr += 2;
					char_cnt -= 2;
				}
				i++;
			}
			temp_ptr++;
		}

		temp_ptr++;
		nsp_address_ptr->omalw_address_ptr->port = sn_nsdl_atoi(temp_ptr, uri_len - (temp_ptr - uri));
	}

	/* IPv4 or Hostname */
	else if(char_cnt == 1)
	{
		char_cnt = 0;
		i = 0;

		/* Check address type */
		while(i < (uri_len - (temp_ptr - uri)))
		{
			if(*(temp_ptr + i) == '.')
				char_cnt++;
			i++;
		}

		/* IPv4 */
		if(char_cnt == 3)
		{
			i = 0;
			char_cnt = 0;

			nsp_address_ptr->omalw_address_ptr->type = SN_NSDL_ADDRESS_TYPE_IPV4;
			nsp_address_ptr->omalw_address_ptr->addr_len = 4;
			nsp_address_ptr->omalw_address_ptr->addr_ptr = sn_nsdl_alloc(4);
			if(!nsp_address_ptr->omalw_address_ptr->addr_ptr)
				return SN_NSDL_FAILURE;

			while(((temp_ptr - uri) < uri_len) && *(temp_ptr - 1) != ':')
			{
				i++;

				if(*(temp_ptr + i) == ':' || *(temp_ptr + i) == '.')
				{
					*(nsp_address_ptr->omalw_address_ptr->addr_ptr + char_cnt) = (uint8_t)sn_nsdl_atoi(temp_ptr, i);
					temp_ptr = temp_ptr + i + 1;
					char_cnt++;
					i = 0;
				}
			}

			nsp_address_ptr->omalw_address_ptr->port = sn_nsdl_atoi(temp_ptr, uri_len - (temp_ptr - uri));
		}

		/* Hostname */
		else
		{
			i = 0;

			nsp_address_ptr->omalw_address_ptr->type = SN_NSDL_ADDRESS_TYPE_HOSTNAME;

			/* Resolve address length */
			if(uri_len > 0xff)
				return SN_NSDL_FAILURE;

			while(((temp_ptr - uri ) + i < uri_len) && *(temp_ptr + i) != ':')
				i++;

			nsp_address_ptr->omalw_address_ptr->addr_len = i;

			/* Copy address */
			nsp_address_ptr->omalw_address_ptr->addr_ptr = sn_nsdl_alloc(i);
			if(!nsp_address_ptr->omalw_address_ptr->addr_ptr)
				return SN_NSDL_FAILURE;

			memcpy(nsp_address_ptr->omalw_address_ptr->addr_ptr, temp_ptr, i);

			temp_ptr += i + 1;

			/* Set port */
			nsp_address_ptr->omalw_address_ptr->port = sn_nsdl_atoi(temp_ptr, uri_len - (temp_ptr - uri));
		}
	}
	else
		return SN_NSDL_FAILURE;

	return SN_NSDL_SUCCESS;
}


int8_t sn_nsdl_process_oma_tlv (uint8_t *data_ptr, uint16_t data_len)
{
	uint8_t *temp_ptr = data_ptr;
	uint8_t type = 0;
	uint16_t identifier = 0;
	uint32_t length = 0;
	uint8_t path_temp[5] = "0/0/x";

	sn_nsdl_resource_info_s resource_temp = {
			.resource_parameters_ptr = 0,
			.mode = SN_GRS_STATIC,
			.pathlen = 5,
			.path = path_temp,
			.resourcelen = 0,
			.resource = 0,
			.access = (sn_grs_resource_acl_e) 0x0f, /* All allowed */
			.sn_grs_dyn_res_callback = 0
	};

	while((temp_ptr - data_ptr) < data_len)
	{
		/* Save type for future use */
		type = *temp_ptr++;

		/* * Bit 5: Indicates the Length of the Identifier. * */
		if(type & 0x20)
		{
			/* 1=The Identifier field of this TLV is 16 bits long */
			identifier = (uint8_t)(*temp_ptr++) << 8;
			identifier += (uint8_t)*temp_ptr++;
		}
		else
		{
			/* 0=The Identifier field of this TLV is 8 bits long */
			identifier = (uint8_t)*temp_ptr++;
		}

		/* * Bit 4-3: Indicates the type of Length. * */
		if((type & 0x18) == 0)
		{
			/* 00 = No length field, the value immediately follows the Identifier field in is of the length indicated by Bits 2-0 of this field */
			length = (type & 0x07);
		}
		else if((type & 0x18) == 0x08)
		{
			/* 01 = The Length field is 8-bits and Bits 2-0 MUST be ignored */
			length = *temp_ptr++;
		}
		else if((type & 0x18) == 0x10)
		{
			/* 10 = The Length field is 16-bits and Bits 2-0 MUST be ignored */
			length = (uint8_t)(*temp_ptr++) << 8;
			length += (uint8_t)*temp_ptr++;
		}
		else if((type & 0x18) == 0x18)
		{
			/* 11 = The Length field is 24-bits and Bits 2-0 MUST be ignored */
			length = (uint8_t)(*temp_ptr++);
			length = length << 16;
			length += (uint8_t)(*temp_ptr++) << 8;
			length += (uint8_t)*temp_ptr++;
		}

		/* * Bits 7-6: Indicates the type of Identifier. * */
		if((type & 0xC0) == 0x00)
		{
			/* 00 = Object Instance in which case the Value contains one or more Resource TLVs */
			/* Not implemented, return failure */
		}
		else if((type & 0xC0) == 0xC0)
		{
			/* 11 = Resource with Value */
			switch(identifier)
			{
			case 0:
				/* Resolve LWM2M Server URI */
				sn_nsdl_resolve_lwm2m_address(temp_ptr, length);
				path_temp[4] = '0';
				resource_temp.resource = temp_ptr;
				resource_temp.resourcelen = length;
				if(sn_grs_create_resource(&resource_temp) != SN_NSDL_SUCCESS)
					return SN_NSDL_FAILURE;
				break;
			case 2:
				/* Resolve security Mode */
				nsp_address_ptr->omalw_server_security = (omalw_server_security_t)sn_nsdl_atoi(temp_ptr, length);
				path_temp[4] = '2';
				resource_temp.resource = temp_ptr;
				resource_temp.resourcelen = length;
				if(sn_grs_create_resource(&resource_temp) != SN_NSDL_SUCCESS)
					return SN_NSDL_FAILURE;

				break;
			case 3:
				/* Public Key or Identity */
				path_temp[4] = '3';
				resource_temp.resource = temp_ptr;
				resource_temp.resourcelen = length;
				if(sn_grs_create_resource(&resource_temp) != SN_NSDL_SUCCESS)
					return SN_NSDL_FAILURE;
				break;
			case 4:
				/* Server Public Key or Identity */;
				path_temp[4] = '4';
				resource_temp.resource = temp_ptr;
				resource_temp.resourcelen = length;
				if(sn_grs_create_resource(&resource_temp) != SN_NSDL_SUCCESS)
					return SN_NSDL_FAILURE;

				break;
			case 5:
				/* Secret Key */
				path_temp[4] = '5';
				resource_temp.resource = temp_ptr;
				resource_temp.resourcelen = length;
				if(sn_grs_create_resource(&resource_temp) != SN_NSDL_SUCCESS)
					return SN_NSDL_FAILURE;

				break;
			default:
				break;
			}

			/* Move pointer to next TLV message */
			temp_ptr += length;
		}
	}

	return SN_NSDL_SUCCESS;
}

static void sn_nsdl_check_oma_bs_status(void)
{
	/* Check OMA BS status */
	if((nsp_address_ptr->omalw_server_security == PSK) && (nsp_address_ptr->omalw_address_ptr->type != SN_NSDL_ADDRESS_TYPE_NONE))
	{
		/* call cb that oma bootstrap is done */
		sn_nsdl_oma_bs_done_cb(nsp_address_ptr);
	}
	else if((nsp_address_ptr->omalw_server_security == CERTIFICATE) && (nsp_address_ptr->omalw_address_ptr->type != SN_NSDL_ADDRESS_TYPE_NONE)&&
			((sn_nsdl_get_resource(5, (void*)"0/0/5") != 0) &&
			(sn_nsdl_get_resource(5, (void*)"0/0/4") != 0) &&
			(sn_nsdl_get_resource(5, (void*)"0/0/3") != 0)) )
	{
		sn_nsdl_oma_bs_done_cb(nsp_address_ptr);
	}
}
