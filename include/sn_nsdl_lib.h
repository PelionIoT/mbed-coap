/**
 * \file sn_nsdl_lib.h
 *
 * \brief NanoService Devices Library header file
 *
 *  Created on: Aug 23, 2011
 *      Author: tero
 *
 */

#ifndef SN_NSDL_LIB_H_
#define SN_NSDL_LIB_H_

#include "ns_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_NSDL_CONST_MEMORY_ATTRIBUTE

#define SN_NSDL_ENDPOINT_NOT_REGISTERED  0
#define SN_NSDL_ENDPOINT_IS_REGISTERED   1

/**
 * \brief Received device server security
 */
typedef enum omalw_server_security_
{
	SEC_NOT_SET = -1,
	PSK = 0,
	RPK = 1,
	CERTIFICATE = 2,
	NO_SEC = 3
}omalw_server_security_t;

/**
 * \brief Endpoint binding and mode
 */
typedef enum sn_nsdl_oma_binding_and_mode_
{
	BINDING_MODE_NOT_SET = 0,
	BINDING_MODE_U = 0x01,
	BINDING_MODE_Q = 0x02,
	BINDING_MODE_S = 0x04
} sn_nsdl_oma_binding_and_mode_t;

/**
 * \brief Endpoint registration mode.
 * 		If REGISTER_WITH_RESOURCES, endpoint sends list of all resources during registration.
 * 		If REGISTER_WITH_TEMPLATE, endpoint sends registration without resource list. Device server must have
 * 		correctly configured template.
 */
typedef enum sn_nsdl_registration_mode_
{
	REGISTER_WITH_RESOURCES = 0,
	REGISTER_WITH_TEMPLATE
}sn_nsdl_registration_mode_t;


typedef struct omalw_certificate_list_
{
	uint8_t certificate_chain_len;
	uint8_t *certificate_ptr[2];
	uint16_t certificate_len[2];
	uint8_t *own_private_key_ptr;
	uint16_t own_private_key_len;
}omalw_certificate_list_t;

/**
 * \brief Endpoint registration parameters
 */
typedef struct sn_nsdl_ep_parameters_
{
	uint8_t 	*endpoint_name_ptr;						/**< Endpoint name */
	uint8_t  	endpoint_name_len;

	uint8_t		*domain_name_ptr;						/**< Domain to register. If null, NSP uses default domain */
	uint8_t		domain_name_len;

	uint8_t 	*type_ptr;								/**< Endpoint type */
	uint8_t 	type_len;

	uint8_t		*lifetime_ptr;							/**< Endpoint lifetime in seconds. eg. "1200" = 1200 seconds */
	uint8_t		lifetime_len;

	sn_nsdl_registration_mode_t ds_register_mode;		/**< Defines registration mode */
	sn_nsdl_oma_binding_and_mode_t binding_and_mode;	/**< Defines endpoints binding and mode */

} sn_nsdl_ep_parameters_s;

/**
 * \brief For internal use
 */
typedef struct sn_nsdl_sent_messages_
{
	uint16_t	msg_id_number;
	uint8_t		message_type;
	ns_list_link_t	link;
} sn_nsdl_sent_messages_s;

/**
 * \brief Function pointers used for memory allocation and freeing
 */
typedef struct sn_nsdl_mem_
{
	void *(*sn_nsdl_alloc)(uint16_t);
	void (*sn_nsdl_free)(void *);
} sn_nsdl_mem_s;

/**
 * \brief Includes resource path
 */
typedef struct sn_grs_resource_
{
	uint8_t pathlen;
	uint8_t *path;
} sn_grs_resource_s;

/**
 * \brief Table of created resources
 */
typedef struct sn_grs_resource_list_
{
	uint8_t res_count;					/**< Number of resources */
	sn_grs_resource_s *res;
} sn_grs_resource_list_s;

/**
 * \brief Resource access rights
 */
typedef enum sn_grs_resource_acl_
{
	SN_GRS_GET_ALLOWED 	= 0x01 ,
	SN_GRS_PUT_ALLOWED 	= 0x02,
	SN_GRS_POST_ALLOWED	= 0x04,
	SN_GRS_DELETE_ALLOWED 	= 0x08
} sn_grs_resource_acl_e;


typedef enum sn_nsdl_oma_device_error_
{
	NO_ERROR = 0,
	LOW_BATTERY_POWER = 1,
	EXTERNAL_POWER_SUPPLY_OFF = 2,
	GPS_MODULE_FAILURE = 3,
	LOW_RECEIVED_SIGNAL_STRENGTH = 4,
	OUT_OF_MEMORY = 5,
	SMS_FAILURE = 6,
	IP_CONN_FAILURE = 7,
	PERIPHERAL_MALFUNCTION = 8
} sn_nsdl_oma_device_error_t;


/**
 * \brief Used protocol
 */
typedef struct sn_proto_info_
{
	sn_nsdl_capab_e proto;				/**< Only COAP is supported */
} sn_proto_info_s;

/**
 * \brief Defines the resource mode
 */
typedef enum sn_nsdl_resource_mode_
{
	SN_GRS_STATIC,						/**< Static resources have some value that doesn't change */
	SN_GRS_DYNAMIC,						/**< Dynamic resources are handled in application. Therefore one must give function callback pointer to them */
	SN_GRS_DIRECTORY					/**< Directory resources are unused and unsupported */
} sn_nsdl_resource_mode_e;

/**
 * \brief Resource registration parameters
 */
typedef struct sn_nsdl_resource_parameters_
{
	uint8_t		*resource_type_ptr;
	uint16_t	resource_type_len;

	uint8_t		*interface_description_ptr;
	uint16_t	interface_description_len;

	uint8_t		coap_content_type;

	uint8_t		mime_content_type;

	uint8_t		observable;

	uint8_t		registered;

}sn_nsdl_resource_parameters_s;

/**
 * \brief Defines parameters for the resource.
 */
typedef struct sn_nsdl_resource_info_
{
	sn_nsdl_resource_parameters_s 	*resource_parameters_ptr;

	sn_nsdl_resource_mode_e			mode;						/**< STATIC etc.. */

	uint16_t 						pathlen;					/**< Address */
	uint8_t 						*path;

	uint16_t 						resourcelen;				/**< 0 if dynamic resource, resource information in static resource */
	uint8_t 						*resource;					/**< NULL if dynamic resource */

	sn_grs_resource_acl_e 			access;

	uint8_t (*sn_grs_dyn_res_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *, sn_proto_info_s *);

	ns_list_link_t					link;

} sn_nsdl_resource_info_s;

/**
 * \brief Defines OMA device object parameters.
 */
typedef struct sn_nsdl_oma_device_
{
	sn_nsdl_oma_device_error_t error_code;															/**< Error code. Mandatory. Can be more than one */
	uint8_t (*sn_oma_device_boot_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *, sn_proto_info_s *);	/**< Device boot callback function. If defined, this is called when reset request is received */

}sn_nsdl_oma_device_t;

/**
 * \brief Defines OMAlw server information
 */
typedef struct sn_nsdl_oma_server_info_
{
	sn_nsdl_addr_s *omalw_address_ptr;
	omalw_server_security_t omalw_server_security;

}sn_nsdl_oma_server_info_t;

/**
 * \brief Defines endpoint parameters to OMA bootstrap.
 */
typedef struct sn_nsdl_bs_ep_info_
{
	void (*oma_bs_status_cb)(sn_nsdl_oma_server_info_t *);
	sn_nsdl_oma_device_t *device_object;
} sn_nsdl_bs_ep_info_t;




/**
 * \fn extern int8_t sn_nsdl_init	(uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
 *							uint8_t (*sn_nsdl_rx_cb)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
 *							sn_nsdl_mem_s *sn_memory)
 *
 * \brief Initialization function for NSDL library. Initializes NSDL, GRS, HTTP and CoAP.
 *
 * \param *sn_nsdl_tx_callback 	A callback function for sending messages.
 *
 * \param *sn_nsdl_rx_callback 	A callback function for parsed messages. If received message is not CoAP protocol message (eg. ACK), message for GRS (GET, PUT, POST, DELETE) or
 * 								reply for some DS messages (register message etc.), rx callback will be called.
 *
 * \param *sn_memory			Memory structure which includes function pointers to the allocation and free functions.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_init(uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
							uint8_t (*sn_nsdl_rx_cb)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
							sn_nsdl_mem_s *sn_memory);

/**
 * \fn extern uint8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr)
 *
 * \brief Registers endpoint to mbed Device Server.
 *
 * \param *endpoint_info_ptr	Contains endpoint information.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr);

/**
 * \fn extern int8_t sn_nsdl_unregister_endpoint(void)
 *
 * \brief Sends unregister-message to mbed Device Server.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_unregister_endpoint(void);

/**
 * \fn extern int8_t sn_nsdl_update_registration(sn_nsdl_ep_parameters_s *endpoint_parameters_ptr);
 *
 * \brief Update the registration with mbed Device Server.
 *
 * \param *endpoint_info_ptr	Contains endpoint information.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_update_registration(uint8_t *lt_ptr, uint8_t lt_len);

/**
 * \fn extern int8_t sn_nsdl_is_ep_registered(void)
 *
 * \brief Checks if endpoint is registered.
 *
 * \return 1 Endpoint registration is done successfully
 * \return 0 Endpoint is not registered
 */
extern int8_t sn_nsdl_is_ep_registered(void);

/**
 * \fn extern void sn_nsdl_nsp_lost(void);
 *
 * \brief A function to inform mbed Device C client library if application detects a fault in mbed Device Server registration.
 *
 * After calling this function sn_nsdl_is_ep_registered() will return "not registered".
 */
extern void sn_nsdl_nsp_lost(void);

/**
 * \fn extern uint16_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
 *													uint8_t *payload_ptr, uint16_t payload_len,
 *													uint8_t *observe_ptr, uint8_t observe_len,
 *													sn_coap_msg_type_e message_type, uint8_t content_type)
 *
 *
 * \brief Sends observation message to mbed Device Server
 *
 * \param	*token_ptr		Pointer to token to be used
 * \param	token_len		Token length
 * \param	*payload_ptr	Pointer to payload to be sent
 * \param	payload_len		Payload length
 * \param	*observe_ptr	Pointer to observe number to be sent
 * \param	observe_len		Observe number len
 * \param	message_type	Observation message type (confirmable or non-confirmable)
 * \param	contetnt_type	Observation message payload contetnt type
 *
 * \return	!0	Success, observation messages message ID
 * \return	0	Failure
 */
extern uint16_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
													uint8_t *payload_ptr, uint16_t payload_len,
													uint8_t *observe_ptr, uint8_t observe_len,
													sn_coap_msg_type_e message_type, uint8_t content_type);

/**
 * \fn extern uint32_t sn_nsdl_get_version(void)
 *
 * \brief Version query function.
 *
 * Used to retrieve the version information from the mbed Device C Client library.
 *
 * \return Pointer to library version string
*/
extern char *sn_nsdl_get_version(void);

/**
 * \fn extern int8_t sn_nsdl_process_coap(uint8_t *packet, uint16_t packet_len, sn_nsdl_addr_s *src)
 *
 * \brief To push CoAP packet to mbed Device C Client library
 *
 * Used to push an CoAP packet to mbed Device C Client library for processing.
 *
 * \param	*packet  Pointer to a uint8_t array containing the packet (including the CoAP headers).
 *      After successful execution this array may contain the response packet.
 *
 * \param	*packet_len	Pointer to length of the packet. After successful execution this array may contain the length
 *      of the response packet.
 *
 * \param	*src	Pointer to packet source address information. After successful execution this array may contain
 *      the destination address of the response packet.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_process_coap(uint8_t *packet, uint16_t packet_len, sn_nsdl_addr_s *src);

/**
 * \fn extern int8_t sn_nsdl_exec(uint32_t time);
 *
 * \brief CoAP retransmission function.
 *
 * Used to give execution time for the mbed Device C Client library for retransmissions.
 *
 * \param  time Time in seconds.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_exec(uint32_t time);

/**
 * \fn  extern int8_t sn_nsdl_create_resource(sn_nsdl_resource_info_s *res)
 *
 * \brief Resource creating function.
 *
 * Used to create a static or dynamic CoAP resource.
 *
 * \param	*res	Pointer to a structure of type sn_nsdl_resource_info_t that contains the information
 *     about the resource.
 *
 * \return	0	Success
 * \return	-1	Failure
 * \return	-2	Resource already exists
 * \return	-3	Invalid path
 * \return	-4	List adding failure
 */
extern int8_t sn_nsdl_create_resource(sn_nsdl_resource_info_s *res);

/**
 * \fn extern int8_t sn_nsdl_update_resource(sn_nsdl_resource_info_s *res)
 *
 * \brief Resource updating function.
 *
 * Used to update the direct value of a static resource, the callback function pointer of a dynamic resource
 * and access rights of the recource.
 *
 * \param	*res	Pointer to a structure of type sn_nsdl_resource_info_t that contains the information
 *     about the resource. Only the pathlen and path elements are evaluated along with
 *     either resourcelen and resource or the function pointer.
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_update_resource(sn_nsdl_resource_info_s *res);

/**
 * \fn extern int8_t sn_nsdl_delete_resource(uint8_t pathlen, uint8_t *path)
 *
 * \brief Resource delete function.
 *
 * Used to delete a resource. If resource has a subresources, these all must also be removed.
 *
 * \param	pathlen		Contains the length of the path that is to be deleted (excluding possible trailing "\0").
 *
 * \param	*path_ptr	A pointer to an array containing the path.
 *
 * \return	0	Success
 * \return	-1	Failure (No such resource)
 */
extern int8_t sn_nsdl_delete_resource(uint16_t pathlen, uint8_t *path);

/**
 * \fn extern sn_nsdl_resource_info_s *sn_nsdl_get_resource(uint16_t pathlen, uint8_t *path)
 *
 * \brief Resource get function.
 *
 * Used to get a resource.
 *
 * \param	pathlen	Contains the length of the path that is to be returned (excluding possible trailing '\0').
 *
 * \param	*path	A pointer to an array containing the path.
 *
 * \return	!NULL	Success, pointer to a sn_nsdl_resource_info_s that contains the resource information\n
 * \return	NULL	Failure
 */
extern sn_nsdl_resource_info_s *sn_nsdl_get_resource(uint16_t pathlen, uint8_t *path);

/**
 * \fn extern sn_grs_resource_list_s *sn_nsdl_list_resource(uint16_t pathlen, uint8_t *path)
 *
 * \brief Resource list function.
 *
 * \param	pathlen	Contains the length of the target path (excluding possible trailing '\0').
 *     The length value is not examined if the path itself is a NULL pointer.
 *
 * \param	*path	A pointer to an array containing the path or a NULL pointer.
 *
 * \return	!NULL	A pointer to a sn_grs_resource_list_s structure containing the resource listing.
 * \return	NULL	Failure with an unspecified error
 */
extern sn_grs_resource_list_s *sn_nsdl_list_resource(uint16_t pathlen, uint8_t *path);

/**
 * \fn extern void sn_nsdl_free_resource_list(sn_grs_resource_list_s *)
 *
 * \brief Free a resource list obtained from sn_nsdl_list_resource()
 *
 * \param	list	The list to free, or NULL.
 */
extern void sn_nsdl_free_resource_list(sn_grs_resource_list_s *list);

/**
 * \fn extern int8_t sn_nsdl_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);
 *
 * \brief Send an outgoing CoAP request.
 *
 * \param	*address_ptr	Pointer to source address struct
 *
 * \param	*coap_hdr_ptr	Pointer to CoAP message to be sent
 *
 * \return	0	Success
 * \return	-1	Failure
 */
extern int8_t sn_nsdl_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);

/**
 * \fn extern int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port, sn_nsdl_addr_type_e address_type);
 *
 * \brief This function is used to set the mbed Device Server address given by an application.
 *
 * \return	0	Success
 * \return	-1	Failed to indicate that internal address pointer is not allocated (call nsdl_init() first).
 */
extern int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port, sn_nsdl_addr_type_e address_type);

/**
 * \fn extern int8_t sn_nsdl_destroy(void);
 *
 * \brief This function releases all allocated memory in mbed Device C Client library.
 */
extern int8_t sn_nsdl_destroy(void);

/**
 * \fn extern int8_t sn_nsdl_oma_bootstrap(sn_nsdl_addr_s *bootstrap_address_ptr, sn_nsdl_ep_parameters_s *endpoint_info_ptr, sn_nsdl_bs_ep_info_t *bootstrap_endpoint_info_ptr);
 *
 * \brief Starts OMA bootstrap process
 */
extern int8_t sn_nsdl_oma_bootstrap(sn_nsdl_addr_s *bootstrap_address_ptr, sn_nsdl_ep_parameters_s *endpoint_info_ptr, sn_nsdl_bs_ep_info_t *bootstrap_endpoint_info_ptr);

/**
 * \fn extern omalw_certificate_list_t *sn_nsdl_get_certificates(uint8_t certificate_chain);
 *
 * \brief Get pointer to received device server certificates
 */
extern omalw_certificate_list_t *sn_nsdl_get_certificates(void);

/**
 * \fn extern int8_t sn_nsdl_set_certificates(omalw_certificate_list_t* certificate_ptr, uint8_t certificate_chain);
 *
 * \brief Updates certificate pointers to resource server.
 */
extern int8_t sn_nsdl_set_certificates(omalw_certificate_list_t* certificate_ptr, uint8_t certificate_chain);

/**
 * \fn extern int8_t sn_nsdl_create_oma_device_object(sn_nsdl_oma_device_t *device_object_ptr);
 *
 * \brief Creates new device object resource
 */
extern int8_t sn_nsdl_create_oma_device_object(sn_nsdl_oma_device_t *device_object_ptr);

#ifdef __cplusplus
}
#endif

#endif /* SN_NSDL_LIB_H_ */
