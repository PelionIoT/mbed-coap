
/* Debug--> */

#define SN_NSDL_CONST_MEMORY_ATTRIBUTE

/* <-- Debug */

#define RESOURCE_DIR_LEN				2
#define RESOURCE_DIR_PATH				{'r','d'}

#define EP_NAME_PARAMETERS_LEN			2
#define EP_NAME_PARAMETERS				{'h','='}

#define RT_PARAMETER_LEN				3
#define RT_PARAMETER					{'r','t','='}

#define IF_PARAMETER_LEN				3
#define IF_PARAMETER					{'i','f','='}

#define CON_PARAMETER_LEN				4
#define CON_PARAMETER					{'c','o','n','='}

#define LT_PARAMETER_LEN				3
#define LT_PARAMETER					{'l','t','='}

#define OBS_PARAMETER_LEN				3
#define OBS_PARAMETER					{'o','b','s'}

#define COAP_CON_PARAMETER_LEN			3
#define COAP_CON_PARAMETER				{'c','t','='}

#define EVENT_PATH_LEN					6
#define EVENT_PATH						{'e','v','e','n','t','/'}

#define SN_NSDL_EP_REGISTER_MESSAGE		1
#define SN_NSDL_EP_UPDATE_MESSAGE		2

#define	SN_NSDL_MSG_NO_TYPE				0
#define	SN_NSDL_MSG_REGISTER			1
#define SN_NSDL_MSG_UNREGISTER			2
#define SN_NSDL_MSG_UPDATE				3
#define SN_NSDL_MSG_EVENT				4

#define	SN_NSDL_MAX_MESSAGE_COUNT		1

#define SN_NSDL_ENDPOINT_NOT_REGISTERED  0
#define SN_NSDL_ENDPOINT_IS_REGISTERED   1

typedef struct sn_nsdl_ep_parameters_
{
	uint8_t 	*endpoint_name_ptr;
	uint8_t  	endpoint_name_len;

	uint8_t		*domain_name_ptr;
	uint8_t		domain_name_len;

	uint8_t 	*type_ptr;
	uint8_t 	type_len;

	uint8_t 	*contex_ptr;
	uint8_t 	contex_len;

	uint8_t		*lifetime_ptr;
	uint8_t		lifetime_len;

} sn_nsdl_ep_parameters_s;

typedef struct sn_nsdl_sent_messages_
{
	uint16_t	msg_id_number;
	uint8_t		message_type;
}sn_nsdl_sent_messages_s;

typedef struct sn_nsdl_mem_
{
	void *(*sn_nsdl_alloc)(uint16_t);
	void (*sn_nsdl_free)(void *);
}sn_nsdl_mem_s;

typedef struct sn_grs_resource_
{
	uint8_t pathlen;
	uint8_t *path;
}sn_grs_resource_s;

typedef struct sn_grs_resource_list_
{
	uint8_t res_count;				/* Number of resources */
	sn_grs_resource_s *res;
}sn_grs_resource_list_s;

typedef enum sn_nsdl_resource_mode_
{
	SN_GRS_STATIC,
	SN_GRS_DYNAMIC,
	SN_GRS_DIRECTORY
}sn_nsdl_resource_mode_e;

typedef enum sn_grs_resource_mutable_
{
	SN_GRS_GET		= 0x01,
	SN_GRS_POST		= 0x02,
	SN_GRS_PUT		= 0x04,
	SN_GRS_DELETE	= 0x08
}sn_grs_resource_mutable_e;

typedef enum sn_grs_resource_acl_
{
	SN_GRS_GET_ALLOWED 	= 0x01 ,
	SN_GRS_PUT_ALLOWED 	= 0x02,
	SN_GRS_POST_ALLOWED	= 0x04,
	SN_GRS_DELETE_ALLOWED 	= 0x08
}sn_grs_resource_acl_e;

typedef struct sn_proto_info_
{
	sn_nsdl_capab_e proto;
	//union inf
	//{
		//sn_http_options_list_s http_opts;
//		sn_coap_options_list_s coap_opts;
	//}
}sn_proto_info_s;

typedef struct sn_nsdl_resource_info_
{
	sn_nsdl_resource_parameters_s 	*resource_parameters_ptr;

	//sn_nsdl_capab_e 				type;						// HTTP, HTTPS, COAP
	sn_nsdl_resource_mode_e 			mode;						// STATIC etc..

	uint16_t 						pathlen;					// Address
	uint8_t 						*path;

	uint8_t 						resourcelen;				// 0 if dynamic resource, resource information in static resource
	uint8_t 						*resource;					// NULL if dynamic resource

	sn_grs_resource_acl_e 			access;
	//sn_grs_resource_mutable_e 		mutable;					// Get, post, put, delete

	uint8_t (*sn_grs_dyn_res_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *, sn_proto_info_s *);

} sn_nsdl_resource_info_s;

///*
// * \brief This function can be used to create a simple static resource of any type.
// * This resource is non-observable, static (meaning that it wont change and NSDL library replies to GET requests.
// * @param A simple resource structure used often in application.
// * @return 0 in case of success,
// * @return -1 in case of being unable to allocate memory for the structure.
// * @return -2 in case of being unable to allocate memory for the resource parameters
// * @return -11 Resource already exists
// * @return -12 Invalid path
// * @return -13 List adding failure
// *
// * NOTE: DOES NOT FREE "resource" parameter.
// */
//typedef struct sn_nsdl_static_resource_struct_t
//{
//	uint8_t * resource_path;
//	uint16_t resource_path_len;
//
//	uint8_t * resource_type;
//	uint16_t resource_type_len;
//
//	uint8_t * resource_value;
//	uint16_t resource_value_len;
//}sn_nsdl_static_resource_struct_t;
//int8_t sn_nsdl_create_simple_static_resource(sn_nsdl_static_resource_struct_t *resource);
/**
 * \fn extern int8_t sn_nsdl_init	(uint8_t (*sn_grs_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
 * 									uint8_t (*sn_grs_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
 * 									sn_grs_mem_s *sn_memory)
 *
 *
 * \brief Initialization function for NSDL library. Initializes NSDL, GRS, HTTP and CoAP.
 *
 * \param *sn_grs_tx_callback 	A callback function for sending messages.
 *
 * \param *sn_grs_rx_callback 	A callback function for parsed messages. If received message is not CoAP protocol message (eg. ACK), message for GRS (GET, PUT, POST, DELETE) or
 * 								reply for some NSDL message (register message etc.), rx callback will be called.
 *
 * \param *sn_memory			Memory structure which includes function pointers to the allocation and free functions.
 *
 * \return						SN_NSDL_SUCCESS = 0, Failed = -1
 */
int8_t sn_nsdl_init	(uint8_t (*sn_grs_tx_callback)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
							uint8_t (*sn_grs_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
							sn_nsdl_mem_s *sn_memory);

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
int8_t sn_nsdl_register_endpoint(sn_nsdl_ep_parameters_s *endpoint_info_ptr);

/**
 * \fn extern int8_t sn_nsdl_unregister_endpoint(void)
 *
 *
 * \brief Sends unregister-message to NSP server.
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
int8_t sn_nsdl_unregister_endpoint(void);
int8_t sn_nsdl_update_registration (sn_nsdl_ep_parameters_s *endpoint_parameters_ptr);
int8_t sn_nsdl_send_eventing_message (uint8_t *event_name_ptr, uint16_t event_name_len, uint8_t *message_body_ptr, uint16_t message_body_len);

/**
 * \fn extern int8_t sn_nsdl_is_ep_registered(void)
 *
 *
 * \brief Checks if endpoint is registered.
 *
 * \return 1 if endpointi registration is done SN_NSDL_SUCCESSfully, 0 if endpoint is not registered
 */
int8_t sn_nsdl_is_ep_registered(void);

/*
 * A function to inform NSDL-C library if application detects a fault in NSP registration. After calling this function
 * , sn_nsdl_is_ep_registered() will return "not registered".
 */
void sn_nsdl_nsp_lost(void);
/**
 * \fn extern int8_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len,
 *															uint8_t *payload_ptr, uint16_t payload_len,
 *															uint8_t *observe_ptr, uint8_t observe_len)
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
 *
 * \return		SN_NSDL_SUCCESS = 0, Failed = -1
 */
extern int8_t sn_nsdl_send_observation_notification(uint8_t *token_ptr, uint8_t token_len, uint8_t *payload_ptr, uint16_t payload_len, uint8_t *observe_ptr, uint8_t observe_len);
int16_t sn_nsdl_get_capability(void);
uint32_t sn_nsdl_get_version(void);
int8_t sn_nsdl_process_http(uint8_t *packet, uint16_t *packet_len, sn_nsdl_addr_s *src);
int8_t sn_nsdl_process_coap(uint8_t *packet, uint16_t packet_len, sn_nsdl_addr_s *src);
int8_t sn_nsdl_exec(uint32_t time);
int8_t sn_nsdl_create_resource(sn_nsdl_resource_info_s *res);
int8_t sn_nsdl_update_resource(sn_nsdl_resource_info_s *res);
int8_t sn_nsdl_delete_resource(uint8_t pathlen, uint8_t *path);
sn_nsdl_resource_info_s *sn_nsdl_get_resource(uint8_t pathlen, uint8_t *path);
sn_grs_resource_list_s *sn_nsdl_list_resource(uint8_t pathlen, uint8_t *path);
uint8_t sn_nsdl_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);
/*
 * \brief This function is used to set the NSP address given by an application.
 * @return 0 on success, -1 on false to indicate that NSDL internal address pointer is not allocated (call nsdl_init() first).
 */
int8_t set_NSP_address(uint8_t *NSP_address, uint16_t port);
/*
 * \brief A function to request SN internal version information out of NSDL library in case of "error reporting" or similar.
 * @return A string with \0 in the end. A human readable format. Please deliver this item to Sensinode in case if you're to report of errors.
 */
//extern const char __code * sn_nsdl_get_library_version_info(void);
