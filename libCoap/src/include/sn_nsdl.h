/**
 * \file sn_nsdl.h
 *
 * \brief NanoService Devices Library generic header file
 *
 *  Created on: Aug 23, 2011
 *      Author: tero
 *
 */

#ifndef SN_NSDL_H_
#define SN_NSDL_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

#define SN_GRS_VERSION	                0x0101

#ifndef SN_NSDL_HAVE_HTTP_CAPABILITY
#define SN_NSDL_HAVE_HTTP_CAPABILITY		0
#endif

#ifndef SN_NSDL_HAVE_HTTPS_CAPABILITY
#define SN_NSDL_HAVE_HTTPS_CAPABILITY	0
#endif

#ifndef SN_NSDL_HAVE_COAP_CAPABILITY
#define SN_NSDL_HAVE_COAP_CAPABILITY		1
#endif

/* * * Common * * */

#define SN_NSDL_SUCCESS  0
#define SN_NSDL_FAILURE (-1)

/* * * * * * * * * * * * * * */
/* * * * ENUMERATIONS  * * * */
/* * * * * * * * * * * * * * */


typedef enum sn_nsdl_capab_
{
    SN_NSDL_PROTOCOL_HTTP           = 0x01,
    SN_NSDL_PROTOCOL_HTTPS          = 0x02,
    SN_NSDL_PROTOCOL_COAP           = 0x04
} sn_nsdl_capab_e;

typedef enum sn_nsdl_addr_type_
{
    SN_NSDL_ADDRESS_TYPE_IPV6       = 0x01,
    SN_NSDL_ADDRESS_TYPE_IPV4       = 0x02,
    SN_NSDL_ADDRESS_TYPE_HOSTNAME   = 0x03,
    SN_NSDL_ADDRESS_TYPE_NONE       = 0xFF
} sn_nsdl_addr_type_e;


#define SN_NDSL_RESOURCE_NOT_REGISTERED	0
#define SN_NDSL_RESOURCE_REGISTERING	1
#define SN_NDSL_RESOURCE_REGISTERED		2


/* * * * * * * * * * * * * */
/* * * * STRUCTURES  * * * */
/* * * * * * * * * * * * * */

/* Address structure of Packet data */
typedef struct sn_nsdl_addr_
{
    sn_nsdl_addr_type_e     type;

    uint8_t                 addr_len;
    uint8_t                *addr_ptr;

    uint16_t                port;

    void					*socket_information;

} sn_nsdl_addr_s;

/* This structure is returned by sn_coap_exec() for sending */
typedef struct sn_nsdl_transmit_
{
    sn_nsdl_addr_s         *dst_addr_ptr;

    sn_nsdl_capab_e         protocol;

    uint16_t                packet_len;
    uint8_t                *packet_ptr;
} sn_nsdl_transmit_s;

typedef struct registration_info_
{
	uint8_t *endpoint_ptr;
	uint8_t endpoint_len;

	uint8_t *endpoint_type_ptr;
	uint8_t endpoint_type_len;

	uint8_t *links_ptr;
	uint16_t links_len;

}registration_info_t;

#endif /* SN_NSDL_H_ */
