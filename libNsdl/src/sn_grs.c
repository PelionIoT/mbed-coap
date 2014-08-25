/**
 *
 * \file sn_grs.c
 * \brief General resource server for Sensinode NanoService platforms
 *
 *
 *
 */
#include <string.h>			// for memcomp
#include <stdlib.h>

#include "ns_types.h"
#include "nsdl_types.h"

#include "sn_nsdl.h"

#if defined(SN_NSDL_HAVE_COAP_CAPABILITY)
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#endif

#include "sn_nsdl_lib.h"
#include "sn_grs.h"


/* Defines */
#define WELLKNOWN_PATH_LEN				16
#define WELLKNOWN_PATH					(".well-known/core")

/* Local static function prototypes */
static int8_t 						sn_grs_resource_info_free			(sn_nsdl_resource_info_s *resource_ptr);
static uint8_t *					sn_grs_convert_uri					(uint16_t *uri_len, uint8_t *uri_ptr);
static int8_t 						sn_grs_add_resource_to_list			(sn_nsdl_resource_info_s *resource_ptr);
#ifdef CC8051_PLAT
void 								copy_code_nsdl						(uint8_t * ptr, prog_uint8_t * code_ptr, uint16_t len);
#endif
static uint8_t 						sn_grs_compare_code					(uint8_t * ptr, prog_uint8_t * code_ptr, uint8_t len);

/* Extern function prototypes */
extern int8_t 						sn_nsdl_build_registration_body		(sn_coap_hdr_s *message_ptr, uint8_t updating_registeration);


/* Local global variables */
SN_MEM_ATTR_GRS_DECL static NS_LIST_DEFINE(resource_root_list, sn_nsdl_resource_info_s, link);
SN_MEM_ATTR_GRS_DECL static const sn_nsdl_resource_info_s *sn_grs_current_resource;
SN_MEM_ATTR_GRS_DECL static uint16_t resource_root_count;


/* Local global function pointers */
static void 	*(*sn_grs_alloc)(uint16_t);
static void 	(*sn_grs_free)(void*);
static uint8_t (*sn_grs_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *);
static int8_t (*sn_grs_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *);

/**
 * \fn int8_t sn_grs_destroy(void)
 * \brief This function may be used to flush GRS related stuff when a program exits.
 * @return always 0.
 */
SN_MEM_ATTR_GRS_FUNC extern int8_t sn_grs_destroy(void)
{
	ns_list_foreach_safe(sn_nsdl_resource_info_s, tmp, &resource_root_list)
	{
		ns_list_remove(&resource_root_list, tmp);
		--resource_root_count;
		sn_grs_resource_info_free(tmp);
	}

	return 0;
}


/**
 * \fn int8_t sn_grs_init	(uint8_t (*sn_grs_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t,
 *		sn_nsdl_addr_s *), int8_t (*sn_grs_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *), sn_nsdl_mem_s *sn_memory)
 *
 * \brief GRS library initialize function.
 *
 * This function initializes GRS and CoAP libraries.
 *
 * \param 	sn_grs_tx_callback 		A function pointer to a transmit callback function.
 * \param  *sn_grs_rx_callback_ptr A function pointer to a receiving callback function. If received packet is not for GRS, it will be passed to
 *									upper level (NSDL) to be proceed.
 * \param 	sn_memory 				A pointer to a structure containing the platform specific functions for memory allocation and free.
 *
 * \return success = 0, failure = -1
 *
*/
SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_init	(uint8_t (*sn_grs_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t,
		sn_nsdl_addr_s *), int8_t (*sn_grs_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *), sn_nsdl_mem_s *sn_memory)
{
	/* If application tries to init GRS more than once.. */
	if (sn_grs_alloc)
		return SN_NSDL_FAILURE;

	/* if sn_memory struct is NULL or , return failure */
	if(!sn_memory)
		return SN_NSDL_FAILURE;

	if (sn_memory->sn_nsdl_alloc == NULL ||
		sn_memory->sn_nsdl_free == NULL ||
		sn_grs_tx_callback_ptr == NULL)
	{
		/* There was a null pointer as a parameter */
		return SN_NSDL_FAILURE;
	}

	/* Alloc and free - function pointers  */
	sn_grs_alloc = sn_memory->sn_nsdl_alloc;
	sn_grs_free = sn_memory->sn_nsdl_free;

	/* TX callback function pointer */
	sn_grs_tx_callback = sn_grs_tx_callback_ptr;
	sn_grs_rx_callback = sn_grs_rx_callback_ptr;

	/* Initialize CoAP protocol library, if implemented to library */
#if	SN_NSDL_HAVE_COAP_CAPABILITY
	sn_coap_builder_and_parser_init(sn_memory->sn_nsdl_alloc, sn_memory->sn_nsdl_free);

	if(sn_coap_protocol_init(sn_memory->sn_nsdl_alloc, sn_memory->sn_nsdl_free, sn_grs_tx_callback, sn_grs_rx_callback))
	{
		return SN_NSDL_FAILURE;
	}
#endif

	return SN_NSDL_SUCCESS;
}

/**
 * \fn extern int8_t sn_grs_exec(uint32_t time)
 *
 * \brief CoAP retransmission function.
 *
 *	Used to give execution time for the GRS (CoAP) library for retransmissions. The GRS library
 *	will call the exec functions of all enabled protocol modules.
 *
 *	\param 	time	Time in seconds.
 *
 *	\return  0 = success, -1 = failure
 *
*/
SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_exec(uint32_t time)
{
#if(SN_NSDL_HAVE_COAP_CAPABILITY)
	/* Call CoAP execution function */
	return sn_coap_protocol_exec(time);
#else
	return SN_NSDL_SUCCESS;
#endif
}

/**
 * \fn extern sn_grs_resource_list_s *sn_grs_list_resource(uint16_t pathlen, uint8_t *path)
 *
 * \brief Resource list function
 *
 * \param pathlen	Contains the length of the target path (excluding possible trailing '\0').
 *					The length value is not examined if the path itself is a NULL pointer.
 *
 * \param *path		A pointer to an array containing the path or a NULL pointer.
 *
 * \return !NULL 	A pointer to a sn_grs_resource_list structure containing the resource listing.\n
 *          NULL 	failure with an unspecified error
 */
SN_MEM_ATTR_GRS_FUNC
extern sn_grs_resource_list_s *sn_grs_list_resource(uint16_t pathlen, uint8_t *path)
{
	sn_grs_resource_list_s *grs_resource_list_ptr = NULL;

	/* Allocate memory for the resource list to be filled */
	grs_resource_list_ptr = sn_grs_alloc(sizeof(sn_grs_resource_list_s));
	if(!grs_resource_list_ptr)
		goto fail;

	/* Count resources to the resource list struct */
	grs_resource_list_ptr->res_count = resource_root_count;
	grs_resource_list_ptr->res = NULL;

	/**************************************/
	/* Fill resource structs to the table */
	/**************************************/

	/* If resources in list */
	if(grs_resource_list_ptr->res_count)
	{
		int i;

		/* Allocate memory for resources */
		grs_resource_list_ptr->res = sn_grs_alloc(grs_resource_list_ptr->res_count * sizeof(sn_grs_resource_s));
		if (!grs_resource_list_ptr->res)
			goto fail;

		/* Initialise the pointers to NULL to permit easy cleanup */
		for (i = 0; i < grs_resource_list_ptr->res_count; i++)
		{
			grs_resource_list_ptr->res[i].path = NULL;
			grs_resource_list_ptr->res[i].pathlen = 0;
		}

		i = 0;
		ns_list_foreach(sn_nsdl_resource_info_s, grs_resource_ptr, &resource_root_list)
		{
			/* Copy pathlen to resource list */
			grs_resource_list_ptr->res[i].pathlen = grs_resource_ptr->pathlen;

			/* Allocate memory for path string */
			grs_resource_list_ptr->res[i].path = sn_grs_alloc(grs_resource_list_ptr->res[i].pathlen);
			if (!grs_resource_list_ptr->res[i].path)
				goto fail;

			/* Copy pathstring to resource list */
			memcpy(grs_resource_list_ptr->res[i].path, grs_resource_ptr->path, grs_resource_ptr->pathlen);

			i++;
		}
	}
	return grs_resource_list_ptr;

fail:
	sn_grs_free_resource_list(grs_resource_list_ptr);
	return NULL;
}

/**
 * \fn extern void sn_grs_free_resource_list(sn_grs_resource_list_s *list)
 *
 * \brief Resource list function
 *
 * \param list		Pointer to resource list to free - may be NULL.
 */
SN_MEM_ATTR_GRS_FUNC
extern void sn_grs_free_resource_list(sn_grs_resource_list_s *list)
{
	if (!list)
		return;

	if (list->res)
	{
		for (int i = 0; i < list->res_count; i++)
		{
			if (list->res[i].path)
			{
				sn_grs_free(list->res[i].path);
				list->res[i].path = NULL;
			}
		}
		sn_grs_free(list->res);
		list->res = NULL;
	}

	sn_grs_free(list);
}

SN_MEM_ATTR_GRS_FUNC
extern const sn_nsdl_resource_info_s *sn_grs_get_first_resource(void)
{

	return sn_grs_current_resource = ns_list_get_first(&resource_root_list);

}

SN_MEM_ATTR_GRS_FUNC
extern const sn_nsdl_resource_info_s *sn_grs_get_next_resource(void)
{

	return sn_grs_current_resource = ns_list_get_next(&resource_root_list, sn_grs_current_resource);

}


/**
 * \fn 	extern int8_t sn_grs_delete_resource(uint16_t pathlen, uint8_t *path_ptr)
 *
 * \brief Resource delete function.
 *
 *	Used to delete a resource. If resource has a subresources, these all must also be removed.
 *
 *	\param 	pathlen		Contains the length of the path that is to be deleted (excluding possible trailing �\0�).
 *
 *	\param 	*path_ptr	A pointer to an array containing the path.
 *
 *	\return 		0 = success, -1 = failure (No such resource)
*/

SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_delete_resource(uint16_t pathlen, uint8_t *path_ptr)
{
	/* Local variables */
	sn_nsdl_resource_info_s 	*resource_temp 	= NULL;

	/* Search if resource found */
	resource_temp = sn_grs_search_resource(pathlen, path_ptr, SN_GRS_SEARCH_METHOD);

	/* If not found */
	if(resource_temp == NULL)
		return SN_NSDL_FAILURE;

	/* If found, delete it and delete also subresources, if there is any */
	do
	{
		/* Remove from list */
		ns_list_remove(&resource_root_list, resource_temp);
		--resource_root_count;

		/* Free */
		sn_grs_resource_info_free(resource_temp);

		/* Search for subresources */
		resource_temp = sn_grs_search_resource(pathlen, path_ptr, SN_GRS_DELETE_METHOD);
	}
	while (resource_temp != NULL);

	return SN_NSDL_SUCCESS;
}



/**
 * \fn 	extern int8_t sn_grs_update_resource(sn_grs_resource_info_s *res)
 *
 * \brief Resource updating function.
 *
 *	Used to update the direct value of a static resource, the callback function pointer of a dynamic resource
 *	and access rights of the recource.
 *
 *	\param 	*res	Pointer to a structure of type sn_grs_resource_info_t that contains the information
 *					about the resource. Only the pathlen and path elements are evaluated along with
 *					either resourcelen and resource or the function pointer.
 *
 *	\return			0 = success, -1 = failure
*/
SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_update_resource(sn_nsdl_resource_info_s *res)
{
	/* Local variables */
	sn_nsdl_resource_info_s 	*resource_temp 	= NULL;

	/* Search resource */
	resource_temp = sn_grs_search_resource(res->pathlen, res->path, SN_GRS_SEARCH_METHOD);
	if(!resource_temp)
		return SN_NSDL_FAILURE;

	/* If there is payload on resource, free it */
	if(resource_temp->resource != NULL)
	{
		sn_grs_free(resource_temp->resource);
		resource_temp->resource = 0;
	}
	/* Update resource len */
	resource_temp->resourcelen = res->resourcelen;

	/* If resource len >0, allocate memory and copy payload */
	if(res->resourcelen)
	{
		resource_temp->resource = sn_grs_alloc(res->resourcelen);
		if(resource_temp->resource == NULL)
		{

			resource_temp->resourcelen = 0;
			return SN_NSDL_FAILURE;

		}

		memcpy(resource_temp->resource, res->resource, resource_temp->resourcelen);
	}

	/* Update access rights and callback address */
	resource_temp->access = res->access;
	resource_temp->sn_grs_dyn_res_callback = res->sn_grs_dyn_res_callback;

	/* TODO: resource_parameters_ptr not copied */

	return SN_NSDL_SUCCESS;
}



/**
 * \fn 	extern int8_t sn_grs_create_resource(sn_grs_resource_info_t *res)
 *
 * \brief Resource creating function.
 *
 *	Used to create a static or dynamic HTTP(S) or CoAP resource.
 *
 *	\param 	*res	Pointer to a structure of type sn_grs_resource_info_t that contains the information
 *					about the resource.
 *
 *	\return 		 0 success
 *					-1 Failure
 *					-2 Resource already exists
 *					-3 Invalid path
 *					-4 List adding failure
*/
SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_create_resource(sn_nsdl_resource_info_s *res)
{

	if(!res)
		return SN_NSDL_FAILURE;

	/* Check path validity */
	if(!res->pathlen || !res->path)
		return SN_GRS_INVALID_PATH;

	/* Check if resource already exists */
	if(sn_grs_search_resource(res->pathlen, res->path, SN_GRS_SEARCH_METHOD) != (sn_nsdl_resource_info_s *)NULL)
	{
		return SN_GRS_RESOURCE_ALREADY_EXISTS;
	}

	if(res->resource_parameters_ptr)
	{
		res->resource_parameters_ptr->registered = SN_NDSL_RESOURCE_NOT_REGISTERED;
	}

	/* Create resource */
	if(sn_grs_add_resource_to_list(res) == SN_NSDL_SUCCESS)
	{
		return SN_NSDL_SUCCESS;
	}
	return SN_GRS_LIST_ADDING_FAILURE;
}



/**
 * \fn 	extern int8_t sn_grs_process_coap(uint8_t *packet, uint16_t *packet_len, sn_nsdl_addr_s *src)
 *
 * \brief To push CoAP packet to GRS library
 *
 *	Used to push an CoAP packet to GRS library for processing.
 *
 *	\param 	*packet		Pointer to a uint8_t array containing the packet (including the CoAP headers).
 *						After successful execution this array may contain the response packet.
 *
 *	\param 	*packet_len	Pointer to length of the packet. After successful execution this array may contain the length
 *						of the response packet.
 *
 *	\param 	*src		Pointer to packet source address information. After successful execution this array may contain
 *						the destination address of the response packet.
 *
 *	\return				0 = success, -1 = failure
*/
SN_MEM_ATTR_GRS_FUNC
extern int8_t sn_grs_process_coap(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *src_addr_ptr)
{

	sn_nsdl_resource_info_s	*resource_temp_ptr	= NULL;
	sn_coap_msg_code_e 		status 				= COAP_MSG_CODE_EMPTY;
	sn_coap_hdr_s 			*response_message_hdr_ptr = NULL;

	if(coap_packet_ptr->msg_code <= COAP_MSG_CODE_REQUEST_DELETE)
	{
		/* Check if .well-known/core */
		if(coap_packet_ptr->uri_path_len == WELLKNOWN_PATH_LEN && sn_grs_compare_code(coap_packet_ptr->uri_path_ptr, (const uint8_t*)WELLKNOWN_PATH, WELLKNOWN_PATH_LEN) == 0)
		{

			sn_coap_content_format_e wellknown_content_format = COAP_CT_LINK_FORMAT;

			/* Allocate resopnse message  */
			response_message_hdr_ptr = sn_grs_alloc(sizeof(sn_coap_hdr_s));
			if(!response_message_hdr_ptr)
			{
				if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
				{
					sn_grs_free(coap_packet_ptr->payload_ptr);
					coap_packet_ptr->payload_ptr = 0;
				}
				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				return SN_NSDL_FAILURE;
			}
			memset(response_message_hdr_ptr, 0, sizeof(sn_coap_hdr_s));

			/* Build response */
			response_message_hdr_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
			response_message_hdr_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			response_message_hdr_ptr->msg_id = coap_packet_ptr->msg_id;
			response_message_hdr_ptr->content_type_len = 1;
			response_message_hdr_ptr->content_type_ptr = malloc(1);
			if(!response_message_hdr_ptr)
			{
				if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
				{
					sn_grs_free(coap_packet_ptr->payload_ptr);
					coap_packet_ptr->payload_ptr = 0;
				}
				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				sn_grs_free(response_message_hdr_ptr);
				return SN_NSDL_FAILURE;
			}

			*response_message_hdr_ptr->content_type_ptr = wellknown_content_format;


			sn_nsdl_build_registration_body(response_message_hdr_ptr, 0);

			/* Send and free */
			sn_grs_send_coap_message(src_addr_ptr, response_message_hdr_ptr);

			if(response_message_hdr_ptr->payload_ptr)
			{
				sn_grs_free(response_message_hdr_ptr->payload_ptr);
				response_message_hdr_ptr->payload_ptr = 0;
			}
			sn_coap_parser_release_allocated_coap_msg_mem(response_message_hdr_ptr);

			/* Free parsed CoAP message */
			if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
			{
				sn_grs_free(coap_packet_ptr->payload_ptr);
				coap_packet_ptr->payload_ptr = 0;
			}
			sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);

			return SN_NSDL_SUCCESS;
		}

		/* Get resource */
		resource_temp_ptr = sn_grs_search_resource(coap_packet_ptr->uri_path_len, coap_packet_ptr->uri_path_ptr, SN_GRS_SEARCH_METHOD);

		/* * * * * * * * * * * */
		/* If resource exists  */
		/* * * * * * * * * * * */
		if(resource_temp_ptr)
		{
			/* If dynamic resource, go to callback */
			if(resource_temp_ptr->mode == SN_GRS_DYNAMIC)
			{
				/* Check accesses */
				if(((coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET) && !(resource_temp_ptr->access & SN_GRS_GET_ALLOWED)) 			||
						((coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST) && !(resource_temp_ptr->access & SN_GRS_POST_ALLOWED)) 	||
						((coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT) && !(resource_temp_ptr->access & SN_GRS_PUT_ALLOWED))   	||
						((coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_DELETE) && !(resource_temp_ptr->access & SN_GRS_DELETE_ALLOWED)))
				{

					status = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
				}
				else
				{
					resource_temp_ptr->sn_grs_dyn_res_callback(coap_packet_ptr, src_addr_ptr,0);
					if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
					{
						sn_grs_free(coap_packet_ptr->payload_ptr);
						coap_packet_ptr->payload_ptr = 0;
					}
					sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
					return SN_NSDL_SUCCESS;
				}
			}
			else
			{
				/* Static resource handling */
				switch (coap_packet_ptr->msg_code )
				{
				case (COAP_MSG_CODE_REQUEST_GET):
					if(resource_temp_ptr->access & SN_GRS_GET_ALLOWED)
					{
						status = COAP_MSG_CODE_RESPONSE_CONTENT;
					}
					else
						status = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
					break;
				case (COAP_MSG_CODE_REQUEST_POST):
					if(resource_temp_ptr->access & SN_GRS_POST_ALLOWED)
					{
						resource_temp_ptr->resourcelen = coap_packet_ptr->payload_len;
						sn_grs_free(resource_temp_ptr->resource);
						resource_temp_ptr->resource = 0;
						if(resource_temp_ptr->resourcelen)
						{
							resource_temp_ptr->resource = sn_grs_alloc(resource_temp_ptr->resourcelen);
							if(!resource_temp_ptr->resource)
							{
								status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
								break;
							}
							memcpy(resource_temp_ptr->resource, coap_packet_ptr->payload_ptr, resource_temp_ptr->resourcelen);
						}
						if(coap_packet_ptr->content_type_ptr)
						{
							if(resource_temp_ptr->resource_parameters_ptr)
							{
								resource_temp_ptr->resource_parameters_ptr->coap_content_type = *coap_packet_ptr->content_type_ptr;
							}
						}
						status = COAP_MSG_CODE_RESPONSE_CHANGED;
					}
					else
						status = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
					break;
				case (COAP_MSG_CODE_REQUEST_PUT):
					if(resource_temp_ptr->access & SN_GRS_PUT_ALLOWED)
					{
						resource_temp_ptr->resourcelen = coap_packet_ptr->payload_len;
						sn_grs_free(resource_temp_ptr->resource);
						resource_temp_ptr->resource = 0;
						if(resource_temp_ptr->resourcelen)
						{
							resource_temp_ptr->resource = sn_grs_alloc(resource_temp_ptr->resourcelen);
							if(!resource_temp_ptr->resource)
							{
								status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
								break;
							}
							memcpy(resource_temp_ptr->resource, coap_packet_ptr->payload_ptr, resource_temp_ptr->resourcelen);
						}
						if(coap_packet_ptr->content_type_ptr)
						{
							if(resource_temp_ptr->resource_parameters_ptr)
							{
								resource_temp_ptr->resource_parameters_ptr->coap_content_type = *coap_packet_ptr->content_type_ptr;
							}
						}
						status = COAP_MSG_CODE_RESPONSE_CHANGED;
					}
					else
						status = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
					break;

				case (COAP_MSG_CODE_REQUEST_DELETE):
					if(resource_temp_ptr->access & SN_GRS_DELETE_ALLOWED)
					{
						if(sn_grs_delete_resource(coap_packet_ptr->uri_path_len, coap_packet_ptr->uri_path_ptr) == SN_NSDL_SUCCESS)
							status = COAP_MSG_CODE_RESPONSE_DELETED;
						else
							status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
					}
					else
						status = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
					break;

				default:
					status = COAP_MSG_CODE_RESPONSE_FORBIDDEN;
					break;
				}
			}
		}

		/* * * * * * * * * * * * * * */
		/* If resource was not found */
		/* * * * * * * * * * * * * * */

		else
		{
			if(coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST ||
					coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
			{
				resource_temp_ptr = sn_grs_alloc(sizeof(sn_nsdl_resource_info_s));
				if(!resource_temp_ptr)
				{
					status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
				}
				else
				{
					memset(resource_temp_ptr, 0, sizeof(sn_nsdl_resource_info_s));

					resource_temp_ptr->access = (sn_grs_resource_acl_e)SN_GRS_DEFAULT_ACCESS;
					resource_temp_ptr->mode = SN_GRS_STATIC;

					resource_temp_ptr->pathlen = coap_packet_ptr->uri_path_len;
					resource_temp_ptr->path = sn_grs_alloc(resource_temp_ptr->pathlen);
					if(!resource_temp_ptr->path)
					{
						sn_grs_free(resource_temp_ptr);
						resource_temp_ptr =  0;
						status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
					}
					else
					{
						memcpy(resource_temp_ptr->path, coap_packet_ptr->uri_path_ptr, resource_temp_ptr->pathlen);

						resource_temp_ptr->resourcelen = coap_packet_ptr->payload_len;
						resource_temp_ptr->resource = sn_grs_alloc(resource_temp_ptr->resourcelen);
						if(!resource_temp_ptr->resource)
						{
							sn_grs_free(resource_temp_ptr->path);
							resource_temp_ptr->path = 0;
							sn_grs_free(resource_temp_ptr);
							resource_temp_ptr = 0;
							status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
						}
						else
						{

							memcpy(resource_temp_ptr->resource, coap_packet_ptr->payload_ptr, resource_temp_ptr->resourcelen);

							ns_list_add_to_start(&resource_root_list, resource_temp_ptr);
							++resource_root_count;
							if(coap_packet_ptr->content_type_ptr)
							{
								if(resource_temp_ptr->resource_parameters_ptr)
								{
									resource_temp_ptr->resource_parameters_ptr->coap_content_type = *coap_packet_ptr->content_type_ptr;
								}
							}
							status = COAP_MSG_CODE_RESPONSE_CREATED;

						}

					}

				}

			}
			else
				status = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
		}

	}


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* If received packed was other than reset, create response  */
	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	if(coap_packet_ptr->msg_type != COAP_MSG_TYPE_RESET && coap_packet_ptr->msg_type != COAP_MSG_TYPE_ACKNOWLEDGEMENT)
	{

		/* Allocate resopnse message  */
		response_message_hdr_ptr = sn_grs_alloc(sizeof(sn_coap_hdr_s));
		if(!response_message_hdr_ptr)
		{
			if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
			{
				sn_grs_free(coap_packet_ptr->payload_ptr);
				coap_packet_ptr->payload_ptr = 0;
			}
			sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
			return SN_NSDL_FAILURE;
		}
		memset(response_message_hdr_ptr, 0, sizeof(sn_coap_hdr_s));

		/* If status has not been defined, response internal server error */
		if(status == COAP_MSG_CODE_EMPTY)
			status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;

		/* Fill header */
		response_message_hdr_ptr->msg_code = status;

		if(coap_packet_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
			response_message_hdr_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
		else
			response_message_hdr_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;

		response_message_hdr_ptr->msg_id = coap_packet_ptr->msg_id;

		if(coap_packet_ptr->token_ptr)
		{
			response_message_hdr_ptr->token_len = coap_packet_ptr->token_len;
			response_message_hdr_ptr->token_ptr = sn_grs_alloc(response_message_hdr_ptr->token_len);
			if(!response_message_hdr_ptr->token_ptr)
			{
				if(response_message_hdr_ptr->payload_ptr)
				{
					sn_grs_free(response_message_hdr_ptr->payload_ptr);
					response_message_hdr_ptr->payload_ptr = 0;
				}
				sn_coap_parser_release_allocated_coap_msg_mem(response_message_hdr_ptr);

				if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
				{
					sn_grs_free(coap_packet_ptr->payload_ptr);
					coap_packet_ptr->payload_ptr = 0;
				}

				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				return SN_NSDL_FAILURE;
			}
			memcpy(response_message_hdr_ptr->token_ptr, coap_packet_ptr->token_ptr, response_message_hdr_ptr->token_len);
		}

		if(status == COAP_MSG_CODE_RESPONSE_CONTENT)
		{
			/* Add content type if other than default */
			if(resource_temp_ptr->resource_parameters_ptr)
			{
				if(resource_temp_ptr->resource_parameters_ptr->coap_content_type != 0)
				{
					response_message_hdr_ptr->content_type_len = 1;
					response_message_hdr_ptr->content_type_ptr = sn_grs_alloc(response_message_hdr_ptr->content_type_len);
					if(!response_message_hdr_ptr->content_type_ptr)
					{
						sn_coap_parser_release_allocated_coap_msg_mem(response_message_hdr_ptr);

						if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
						{
							sn_grs_free(coap_packet_ptr->payload_ptr);
							coap_packet_ptr->payload_ptr = 0;
						}

						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
						return SN_NSDL_FAILURE;
					}
					memcpy(response_message_hdr_ptr->content_type_ptr, &resource_temp_ptr->resource_parameters_ptr->coap_content_type, response_message_hdr_ptr->content_type_len);
				}
			}

			/* Add payload */
			response_message_hdr_ptr->payload_len = resource_temp_ptr->resourcelen;
			response_message_hdr_ptr->payload_ptr = sn_grs_alloc(response_message_hdr_ptr->payload_len);

			if(!response_message_hdr_ptr->payload_ptr)
			{
				sn_coap_parser_release_allocated_coap_msg_mem(response_message_hdr_ptr);

				if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
				{
					sn_grs_free(coap_packet_ptr->payload_ptr);
					coap_packet_ptr->payload_ptr = 0;
				}

				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
				return SN_NSDL_FAILURE;
			}

			memcpy(response_message_hdr_ptr->payload_ptr, resource_temp_ptr->resource, response_message_hdr_ptr->payload_len);
		}

		sn_grs_send_coap_message(src_addr_ptr, response_message_hdr_ptr);

		if(response_message_hdr_ptr->payload_ptr)
		{
			sn_grs_free(response_message_hdr_ptr->payload_ptr);
			response_message_hdr_ptr->payload_ptr = 0;
		}
		sn_coap_parser_release_allocated_coap_msg_mem(response_message_hdr_ptr);
	}

	/* Free parsed CoAP message */
	if(coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr)
	{
		sn_grs_free(coap_packet_ptr->payload_ptr);
		coap_packet_ptr->payload_ptr = 0;
	}
	sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);


	return SN_NSDL_SUCCESS;
}




/**
 * \fn 	extern int16_t sn_grs_get_capability(void)
 *
 * \brief Capability query function.
 *
 *	Used to retrieve the list of supported protocols from the GRS module.
 *
 *	\return				>0 success, supported capabilities reported using bitmask with definitions from sn_grs_capab_t\n
 *						0 success, no supported capabilities\n
*/
SN_MEM_ATTR_GRS_FUNC
extern int16_t sn_grs_get_capability(void)
{
	int16_t capabilities = 0;
	if(SN_NSDL_HAVE_HTTP_CAPABILITY)
		capabilities |= 0x01;

	if(SN_NSDL_HAVE_HTTPS_CAPABILITY)
		capabilities |= 0x02;

	if(SN_NSDL_HAVE_COAP_CAPABILITY)
		capabilities |= 0x04;

	return capabilities;
}


/**
 * \fn 	extern uint32_t sn_grs_get_version(void)
 *
 * \brief Version query function.
 *
 *	Used to retrieve the version information structure from the GRS library.
 *
 *	\return 		!0 MSB 2 bytes major version, LSB 2 bytes minor version.
 *					0 failure
*/
SN_MEM_ATTR_GRS_FUNC
extern uint32_t sn_grs_get_version(void)
{
	return SN_GRS_VERSION;
}

/**
 * \fn 	extern int8_t sn_grs_send_coap_message(sn_nsdl_addr_s * address_ptr, sn_coap_hdr_s *coap_hdr_ptr)
 *
 * \brief Sends CoAP message
 *
 *	Sends CoAP message
 *
 *	\param  *coap_hdr_ptr	Pointer to CoAP message to be sent
 *
 *	\param 	*address_ptr	Pointer to source address struct
 *
 *	\return	0 = success, -1 = failed
 *
*/
extern int8_t sn_grs_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;
	uint8_t		ret_val = 0;

	/* Calculate message length */
	message_len = sn_coap_builder_calc_needed_packet_data_size(coap_hdr_ptr);

	/* Allocate memory for message and check was allocating successfully */
	message_ptr = sn_grs_alloc(message_len);
	if(message_ptr == NULL)
		return SN_NSDL_FAILURE;

	/* Build CoAP message */
	if(sn_coap_protocol_build(address_ptr, message_ptr, coap_hdr_ptr) < 0)
	{
		sn_grs_free(message_ptr);
		message_ptr = 0;
		return SN_NSDL_FAILURE;
	}

	/* Call tx callback function to send message */
	ret_val = sn_grs_tx_callback(SN_NSDL_PROTOCOL_COAP, message_ptr, message_len, address_ptr);

	/* Free allocated memory */
	sn_grs_free(message_ptr);
	message_ptr = 0;

	if(ret_val == 0)
		return SN_NSDL_FAILURE;
	else
		return SN_NSDL_SUCCESS;
}

/**
 * \fn 	static sn_grs_resource_info_s *sn_grs_search_resource(uint16_t pathlen, uint8_t *path, uint8_t search_method)
 *
 * \brief Searches given resource from linked list
 *
 *	Search either precise path, or subresources, eg. dr/x -> returns dr/x/1, dr/x/2 etc...
 *
 *	\param  pathlen			Length of the path to be search
 *
 *	\param 	*path			Pointer to the path string to be search
 *
 *	\param 	search_method	Search method, SEARCH or DELETE
 *
 *	\return					Pointer to the resource. If resource not found, return value is NULL
 *
*/
SN_MEM_ATTR_GRS_FUNC
sn_nsdl_resource_info_s *sn_grs_search_resource(uint16_t pathlen, uint8_t *path, uint8_t search_method)
{
	/* Local variables */
	uint8_t 					*path_temp_ptr 			= NULL;

	/* Check parameters */
	if(!pathlen || !path)
	{
		return NULL;
	}

	/* Remove '/' - marks from the end and beginning */
	path_temp_ptr = sn_grs_convert_uri(&pathlen, path);

	/* Searchs exact path */
	if(search_method == SN_GRS_SEARCH_METHOD)
	{
		/* Scan all nodes on list */
		ns_list_foreach(sn_nsdl_resource_info_s, resource_search_temp, &resource_root_list)
		{
			/* If length equals.. */
			if(resource_search_temp->pathlen == pathlen)
			{
				/* Compare paths, If same return node pointer*/
				if(0 == memcmp(resource_search_temp->path, path_temp_ptr, pathlen))
					return resource_search_temp;
			}
		}
	}

	/* Search also subresources, eg. dr/x -> returns dr/x/1, dr/x/2 etc... */
	else if(search_method == SN_GRS_DELETE_METHOD)
	{
		/* Scan all nodes on list */
		ns_list_foreach(sn_nsdl_resource_info_s, resource_search_temp, &resource_root_list)
		{
			uint8_t *temp_ptr = resource_search_temp->path;

			/* If found, return pointer */
			if((*(temp_ptr+(uint8_t)pathlen) == '/')
					&& !memcmp(resource_search_temp->path, path_temp_ptr, pathlen))
				return resource_search_temp;
		}
	}

	/* If there was not nodes we wanted, return NULL */
	return NULL;
}


/**
 * \fn 	static int8_t sn_grs_add_resource_to_list(sn_grs_resource_info_s *resource_ptr)
 *
 * \brief Adds given resource to resource list
 *
 *	\param 	*resource_ptr			Pointer to the path string to be search
 *
 *	\return	0 = SN_NSDL_SUCCESS, -1 = SN_NSDL_FAILURE
 *
*/
SN_MEM_ATTR_GRS_FUNC
static int8_t sn_grs_add_resource_to_list(sn_nsdl_resource_info_s *resource_ptr)
{
	/* Local variables */
	uint8_t *path_start_ptr = NULL;
	uint16_t path_len = 0;
	sn_nsdl_resource_info_s *resource_copy_ptr = NULL;

		/* Allocate memory for the resource info copy */
	if(!resource_ptr->pathlen)
	{
		return SN_NSDL_FAILURE;
	}
	resource_copy_ptr = sn_grs_alloc(sizeof(sn_nsdl_resource_info_s));
	if(resource_copy_ptr == NULL)
	{
		return SN_NSDL_FAILURE;
	}

	/* Set everything to zero  */
	memset(resource_copy_ptr, 0, sizeof(sn_nsdl_resource_info_s));

	resource_copy_ptr->mode = resource_ptr->mode;
	resource_copy_ptr->resourcelen = resource_ptr->resourcelen;
	resource_copy_ptr->sn_grs_dyn_res_callback = resource_ptr->sn_grs_dyn_res_callback;
	resource_copy_ptr->access = resource_ptr->access;

	/* Remove '/' - chars from the beginning and from the end */

	path_len = resource_ptr->pathlen;
	path_start_ptr = sn_grs_convert_uri(&path_len, resource_ptr->path);

	/* Allocate memory for the path */
	resource_copy_ptr->path = sn_grs_alloc(path_len);
	if(!resource_copy_ptr->path)
	{
		sn_grs_resource_info_free(resource_copy_ptr);
		return SN_NSDL_FAILURE;
	}

	/* Update pathlen */
	resource_copy_ptr->pathlen = path_len;

	/* Copy path string to the copy */
#ifdef CC8051_PLAT
        copy_code_nsdl(resource_copy_ptr->path, (prog_uint8_t*)path_start_ptr, resource_copy_ptr->pathlen);
#else
	memcpy(resource_copy_ptr->path, path_start_ptr, resource_copy_ptr->pathlen);
#endif
	/* Allocate memory for the resource, and copy it to copy */
	if(resource_ptr->resource)
	{
		resource_copy_ptr->resource = sn_grs_alloc(resource_ptr->resourcelen);
		if(!resource_copy_ptr->resource)
		{
			sn_grs_resource_info_free(resource_copy_ptr);
			return SN_NSDL_FAILURE;
		}
		memcpy(resource_copy_ptr->resource, resource_ptr->resource, resource_ptr->resourcelen);
	}



	/* If resource parameters exists, copy them */
	if(resource_ptr->resource_parameters_ptr)
	{
		resource_copy_ptr->resource_parameters_ptr = sn_grs_alloc(sizeof(sn_nsdl_resource_parameters_s));
		if(!resource_copy_ptr->resource_parameters_ptr)
		{
			sn_grs_resource_info_free(resource_copy_ptr);
			return SN_NSDL_FAILURE;
		}

		memset(resource_copy_ptr->resource_parameters_ptr, 0, sizeof(sn_nsdl_resource_parameters_s));


		resource_copy_ptr->resource_parameters_ptr->resource_type_len = resource_ptr->resource_parameters_ptr->resource_type_len;

		resource_copy_ptr->resource_parameters_ptr->interface_description_len = resource_ptr->resource_parameters_ptr->interface_description_len;

		resource_copy_ptr->resource_parameters_ptr->mime_content_type = resource_ptr->resource_parameters_ptr->mime_content_type;

		resource_copy_ptr->resource_parameters_ptr->observable = resource_ptr->resource_parameters_ptr->observable;

		if(resource_ptr->resource_parameters_ptr->resource_type_ptr)
		{
			resource_copy_ptr->resource_parameters_ptr->resource_type_ptr = sn_grs_alloc(resource_ptr->resource_parameters_ptr->resource_type_len);
			if(!resource_copy_ptr->resource_parameters_ptr->resource_type_ptr)
			{
				sn_grs_resource_info_free(resource_copy_ptr);
				return SN_NSDL_FAILURE;
			}
#ifdef CC8051_PLAT
                        copy_code_nsdl(resource_copy_ptr->resource_parameters_ptr->resource_type_ptr,(prog_uint8_t*) resource_ptr->resource_parameters_ptr->resource_type_ptr, resource_ptr->resource_parameters_ptr->resource_type_len);
#else
			memcpy(resource_copy_ptr->resource_parameters_ptr->resource_type_ptr, resource_ptr->resource_parameters_ptr->resource_type_ptr, resource_ptr->resource_parameters_ptr->resource_type_len);
#endif
                }

		if(resource_ptr->resource_parameters_ptr->interface_description_ptr)
		{
			resource_copy_ptr->resource_parameters_ptr->interface_description_ptr = sn_grs_alloc(resource_ptr->resource_parameters_ptr->interface_description_len);
			if(!resource_copy_ptr->resource_parameters_ptr->interface_description_ptr)
			{
				sn_grs_resource_info_free(resource_copy_ptr);
				return SN_NSDL_FAILURE;
			}
			memcpy(resource_copy_ptr->resource_parameters_ptr->interface_description_ptr, resource_ptr->resource_parameters_ptr->interface_description_ptr, resource_ptr->resource_parameters_ptr->interface_description_len);
		}

		/* Copy auto observation parameter */
		/* todo: aobs not supported ATM - needs fixing */
/*		if(resource_ptr->resource_parameters_ptr->auto_obs_ptr && resource_ptr->resource_parameters_ptr->auto_obs_len)
		{
			resource_copy_ptr->resource_parameters_ptr->auto_obs_ptr = sn_grs_alloc(resource_ptr->resource_parameters_ptr->auto_obs_len);
			if(!resource_copy_ptr->resource_parameters_ptr->auto_obs_ptr)
			{
				sn_grs_resource_info_free(resource_copy_ptr);
				return SN_NSDL_FAILURE;
			}
			memcpy(resource_copy_ptr->resource_parameters_ptr->auto_obs_ptr, resource_ptr->resource_parameters_ptr->auto_obs_ptr, resource_ptr->resource_parameters_ptr->auto_obs_len);
			resource_copy_ptr->resource_parameters_ptr->auto_obs_len = resource_ptr->resource_parameters_ptr->auto_obs_len;
		}

		resource_copy_ptr->resource_parameters_ptr->coap_content_type = resource_ptr->resource_parameters_ptr->coap_content_type;
		*/
	}

	/* Add copied resource to the linked list */
	ns_list_add_to_start(&resource_root_list, resource_copy_ptr);
	++resource_root_count;

	return SN_NSDL_SUCCESS;
}


/**
 * \fn 	static uint8_t *sn_grs_convert_uri(uint16_t *uri_len, uint8_t *uri_ptr)
 *
 * \brief Removes '/' from the beginning and from the end of uri string
 *
 *	\param  *uri_len			Pointer to the length of the path string
 *
 *	\param 	*uri_ptr			Pointer to the path string
 *
 *	\return	start pointer of the uri
 *
*/

static uint8_t *sn_grs_convert_uri(uint16_t *uri_len, uint8_t *uri_ptr)
{
	/* Local variables */
	uint8_t *uri_start_ptr = uri_ptr;

	/* If '/' in the beginning, update uri start pointer and uri len */
	if(*uri_ptr == '/')
	{
		uri_start_ptr = uri_ptr+1;
		*uri_len = *uri_len-1;
	}

	/* If '/' at the end, update uri len */
	if(*(uri_start_ptr+*uri_len-1) == '/')
	{
		*uri_len = *uri_len-1;
	}

	/* Return start pointer */
	return uri_start_ptr;
}

/**
 * \fn 	static int8_t sn_grs_resource_info_free(sn_grs_resource_info_s *resource_ptr)
 *
 * \brief Frees resource info structure
 *
 *	\param *resource_ptr	Pointer to the resource
 *
 *	\return	0 if success, -1 if failed
 *
*/
SN_MEM_ATTR_GRS_FUNC
static int8_t sn_grs_resource_info_free(sn_nsdl_resource_info_s *resource_ptr)
{
	if(resource_ptr)
	{
		if(resource_ptr->resource_parameters_ptr)
		{
			if(resource_ptr->resource_parameters_ptr->interface_description_ptr)
			{
				sn_grs_free(resource_ptr->resource_parameters_ptr->interface_description_ptr);
				resource_ptr->resource_parameters_ptr->interface_description_ptr = 0;
			}

			if(resource_ptr->resource_parameters_ptr->resource_type_ptr)
			{
				sn_grs_free(resource_ptr->resource_parameters_ptr->resource_type_ptr);
				resource_ptr->resource_parameters_ptr->resource_type_ptr = 0;
			}

			/* Todo: aobs not supported ATM - needs fixing */
			/*
			if(resource_ptr->resource_parameters_ptr->auto_obs_ptr)
			{
				sn_grs_free(resource_ptr->resource_parameters_ptr->auto_obs_ptr);
				resource_ptr->resource_parameters_ptr->auto_obs_ptr = 0;
			}
			*/

			sn_grs_free(resource_ptr->resource_parameters_ptr);
			resource_ptr->resource_parameters_ptr = 0;
		}

		if(resource_ptr->path)
		{
			sn_grs_free(resource_ptr->path);
			resource_ptr->path = 0;
		}
		if(resource_ptr->resource)
		{
			sn_grs_free(resource_ptr->resource);
			resource_ptr->resource = 0;
		}
		sn_grs_free(resource_ptr);
		resource_ptr = 0;
		return SN_NSDL_SUCCESS;
	}
	return SN_NSDL_FAILURE;
}

#ifdef CC8051_PLAT
void copy_code_nsdl(uint8_t * ptr, prog_uint8_t * code_ptr, uint16_t len)
{
	uint16_t i;
	for(i=0; i<len; i++)
	{
		ptr[i] = code_ptr[i];
	}
}
#endif

static uint8_t sn_grs_compare_code(uint8_t * ptr, prog_uint8_t * code_ptr, uint8_t len)
{
	uint8_t i=0;
	while(len)
	{
		if(ptr[i] != code_ptr[i])
		{
			break;
		}
		len--;
		i++;
	}
	return len;
}

