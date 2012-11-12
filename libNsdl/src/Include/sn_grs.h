/*
 * GRS.h
 *
 *  Created on: 2.8.2011
 *      Author: Tero
 */

#ifndef GRS_H_
#define GRS_H_


#endif /* GRS_H_ */


//#define SUCCESS 				 0
//#define FAILURE 				-1

#define SN_GRS_RESOURCE_ALREADY_EXISTS	-2
#define SN_GRS_INVALID_PATH 			-3
#define SN_GRS_LIST_ADDING_FAILURE		-4
#define SN_GRS_RESOURCE_UPDATED		-5

#define ACCESS_DENIED			-6

#define SN_GRS_DELETE_METHOD	0
#define SN_GRS_SEARCH_METHOD	1

#define SN_GRS_DEFAULT_ACCESS	0x0F

/***** Enumerations *****/

//typedef enum sn_grs_resource_mode_
//{
//	SN_GRS_STATIC,
//	SN_GRS_DYNAMIC,
//	SN_GRS_DIRECTORY
//}sn_grs_resource_mode_e;

//typedef enum sn_grs_resource_mutable_
//{
//	SN_GRS_GET		= 0x01,
//	SN_GRS_POST		= 0x02,
//	SN_GRS_PUT		= 0x04,
//	SN_GRS_DELETE	= 0x08
//}sn_grs_resource_mutable_e;
//
//typedef enum sn_grs_resource_acl_
//{
//	SN_GRS_GET_ALLOWED 	= 0x01 ,
//	SN_GRS_PUT_ALLOWED 	= 0x02,
//	SN_GRS_POST_ALLOWED	= 0x04,
//	SN_GRS_DELETE_ALLOWED 	= 0x08
//}sn_grs_resource_acl_e;



/***** Structs *****/

typedef struct sn_grs_version_
{
	uint8_t major_version;
	uint8_t minor_version;
	uint8_t build;
}sn_grs_version_s;


//typedef struct sn_proto_info_
//{
//	sn_nsdl_capab_e proto;
//	//union inf
//	//{
//		//sn_http_options_list_s http_opts;
//		sn_coap_options_list_s coap_opts;
//	//}
//}sn_proto_info_s;

//typedef struct sn_grs_resource_info_
//{
//	sn_nsdl_resource_parameters_s 	*resource_parameters_ptr;
//
//	//sn_nsdl_capab_e 				type;						// HTTP, HTTPS, COAP
//	sn_grs_resource_mode_e 			mode;						// STATIC etc..
//
//	uint16_t 						pathlen;					// Address
//	uint8_t 						*path;
//
//	uint8_t 						resourcelen;				// 0 if dynamic resource, resource information in static resource
//	uint8_t 						*resource;					// NULL if dynamic resource
//
//	sn_grs_resource_acl_e 			access;
//	//sn_grs_resource_mutable_e 		mutable;					// Get, post, put, delete
//
//	uint8_t (*sn_grs_dyn_res_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *, sn_proto_info_s *);
//
//} sn_grs_resource_info_s;

//typedef struct sn_grs_resource_
//{
//	uint8_t pathlen;
//	uint8_t *path;
//}sn_grs_resource_s;
//
//typedef struct sn_grs_resource_list_
//{
//	uint8_t res_count;				/* Number of resources */
//	sn_grs_resource_s *res;
//}sn_grs_resource_list_s;

//typedef struct sn_grs_mem_
//{
//	void *(*sn_grs_alloc)(uint16_t);
//	void (*sn_grs_free)(void *);
//}sn_grs_mem_s;

/***** Function prototypes *****/
/**
 *	\fn extern int8_t sn_grs_init	(uint8_t (*sn_grs_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t,
 *									sn_nsdl_addr_s *), uint8_t (*sn_grs_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
 *									sn_grs_mem_s *sn_memory)
 *
 *  \brief GRS library initialize function.
 *
 *	This function initializes GRS, CoAP and HTTP libraries.
 *
 *	\param 	sn_grs_tx_callback 		A function pointer to a transmit callback function.
 *	\param  *sn_grs_rx_callback_ptr A function pointer to a receiving callback function. If received packet is not for GRS, it will be passed to
 *									upper level (NSDL) to be proceed.
 *	\param 	sn_memory 				A pointer to a structure containing the platform specific functions for memory allocation and free.
 *
 *	\return success = 0, failure = -1
 *
*/
extern int8_t sn_grs_init	(uint8_t (*sn_grs_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t,
		sn_nsdl_addr_s *), uint8_t (*sn_grs_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *), sn_nsdl_mem_s *sn_memory);
extern int8_t sn_grs_exec(uint32_t time);
extern sn_grs_resource_list_s *sn_grs_list_resource(uint16_t pathlen, uint8_t *path);
extern sn_nsdl_resource_info_s *sn_grs_get_first_resource(void);
extern sn_nsdl_resource_info_s *sn_grs_get_next_resource(void);
extern sn_nsdl_resource_info_s *sn_grs_get_resource(uint16_t pathlen, uint8_t *path);
extern int8_t sn_grs_delete_resource(uint16_t pathlen, uint8_t *path);
extern int8_t sn_grs_update_resource(sn_nsdl_resource_info_s *res);
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
 *					-1 Resource already exists
 *					-2 Invalid path
 *					-3 List adding failure
*/
extern int8_t sn_grs_create_resource(sn_nsdl_resource_info_s *res);
extern int8_t sn_grs_process_http(uint8_t *packet, uint16_t *packet_len, sn_nsdl_addr_s *src);
extern int8_t sn_grs_process_coap(uint8_t *packet, uint16_t packet_len, sn_nsdl_addr_s *src);
extern int16_t sn_grs_get_capability(void);
extern uint32_t sn_grs_get_version(void);
extern uint8_t sn_grs_send_coap_message(sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);

extern int8_t sn_grs_destroy(void);






