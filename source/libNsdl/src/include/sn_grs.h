#ifndef GRS_H_
#define GRS_H_

/*
 * GRS.h
 *
 * Copyright (c) 2011 - 2014, All rights reserved.
 */

#ifdef __cplusplus
extern "C" {
#endif


#define SN_GRS_RESOURCE_ALREADY_EXISTS	-2
#define SN_GRS_INVALID_PATH 			-3
#define SN_GRS_LIST_ADDING_FAILURE		-4
#define SN_GRS_RESOURCE_UPDATED		-5

#define ACCESS_DENIED			-6

#define SN_GRS_DELETE_METHOD	0
#define SN_GRS_SEARCH_METHOD	1

#define SN_GRS_DEFAULT_ACCESS	0x0F

#define SN_NDSL_RESOURCE_NOT_REGISTERED	0
#define SN_NDSL_RESOURCE_REGISTERING	1
#define SN_NDSL_RESOURCE_REGISTERED		2

/***** Structs *****/

typedef struct sn_grs_version_
{
	uint8_t major_version;
	uint8_t minor_version;
	uint8_t build;
}sn_grs_version_s;



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
 *	\param 	sn_grs_tx_callback 		A function pointer to a transmit callback function. Should return 1 when succeed, 0 when failed
 *	\param  *sn_grs_rx_callback_ptr A function pointer to a receiving callback function. If received packet is not for GRS, it will be passed to
 *									upper level (NSDL) to be proceed.
 *	\param 	sn_memory 				A pointer to a structure containing the platform specific functions for memory allocation and free.
 *
 *	\return success = 0, failure = -1
 *
*/
extern int8_t 						sn_grs_init	(uint8_t (*sn_grs_tx_callback_ptr)(sn_nsdl_capab_e , uint8_t *, uint16_t,
										sn_nsdl_addr_s *), int8_t (*sn_grs_rx_callback_ptr)(sn_coap_hdr_s *, sn_nsdl_addr_s *), sn_nsdl_mem_s *sn_memory);
extern const sn_nsdl_resource_info_s *sn_grs_get_first_resource	(void);
extern const sn_nsdl_resource_info_s *sn_grs_get_next_resource	(void);
extern int8_t 						sn_grs_process_coap			(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *src);
extern sn_nsdl_resource_info_s *	sn_grs_search_resource		(uint16_t pathlen, uint8_t *path, uint8_t search_method);
extern int8_t 						sn_grs_destroy				(void);

#ifdef __cplusplus
}
#endif




#endif /* GRS_H_ */
