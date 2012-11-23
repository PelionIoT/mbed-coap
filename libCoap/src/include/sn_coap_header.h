/******************************************************************************
 * \file sn_coap_header.h
 *
 * \brief CoAP C-library User header interface header file
 *
 *  Created on: Jun 30, 2011
 *      Author: pekka_ext
 *
 * \note Supports draft-ietf-core-coap-12
 *****************************************************************************/

#ifndef SN_COAP_HEADER_H_
#define SN_COAP_HEADER_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

/* * * * * * * * * * * * * * */
/* * * * ENUMERATIONS  * * * */
/* * * * * * * * * * * * * * */

/* Enumeration for CoAP Version */
typedef enum coap_version_
{
    COAP_VERSION_1          = 0x40,
    COAP_VERSION_UNKNOWN    = 0xFF
} coap_version_e;

/* Enumeration for CoAP Message type, used in CoAP Header */
typedef enum sn_coap_msg_type_
{
    COAP_MSG_TYPE_CONFIRMABLE       = 0x00, /* User uses this for Reliable Request messages */
    COAP_MSG_TYPE_NON_CONFIRMABLE   = 0x10, /* User uses this for Non-reliable Request and Response messages */
    COAP_MSG_TYPE_ACKNOWLEDGEMENT   = 0X20, /* User uses this for Response to a Confirmable Request  */
    COAP_MSG_TYPE_RESET             = 0x30  /* User uses this to answer a Bad Request */
} sn_coap_msg_type_e;

/* Enumeration for CoAP Message code, used in CoAP Header */
typedef enum sn_coap_msg_code_
{
    COAP_MSG_CODE_EMPTY                                 = 0,
    COAP_MSG_CODE_REQUEST_GET                           = 1,
    COAP_MSG_CODE_REQUEST_POST                          = 2,
    COAP_MSG_CODE_REQUEST_PUT                           = 3,
    COAP_MSG_CODE_REQUEST_DELETE                        = 4,

    COAP_MSG_CODE_RESPONSE_CREATED                      = 65,
    COAP_MSG_CODE_RESPONSE_DELETED                      = 66,
    COAP_MSG_CODE_RESPONSE_VALID                        = 67,
    COAP_MSG_CODE_RESPONSE_CHANGED                      = 68,
    COAP_MSG_CODE_RESPONSE_CONTENT                      = 69,
    COAP_MSG_CODE_RESPONSE_BAD_REQUEST                  = 128,
    COAP_MSG_CODE_RESPONSE_UNAUTHORIZED                 = 129,
    COAP_MSG_CODE_RESPONSE_BAD_OPTION                   = 130,
    COAP_MSG_CODE_RESPONSE_FORBIDDEN                    = 131,
    COAP_MSG_CODE_RESPONSE_NOT_FOUND                    = 132,
    COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED           = 133,
    COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE	            = 134,
    COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE    = 136,	/* Block */
    COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED			= 140,
    COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE     = 141,
    COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT   = 143,
    COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR        = 160,
    COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED              = 161,
    COAP_MSG_CODE_RESPONSE_BAD_GATEWAY                  = 162,
    COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE          = 163,
    COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT              = 164,
    COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED       = 165
} sn_coap_msg_code_e;

/* Enumeration for CoAP Option number, used in CoAP Header */
typedef enum sn_coap_option_numbers_
{
	COAP_OPTION_IF_MATCH		= 1,
	COAP_OPTION_URI_HOST		= 3,
	COAP_OPTION_ETAG			= 4,
	COAP_OPTION_IF_NONE_MATCH	= 5,
	COAP_OPTION_OBSERVE			= 6,
	COAP_OPTION_URI_PORT		= 7,
	COAP_OPTION_LOCATION_PATH	= 8,
	COAP_OPTION_URI_PATH		= 11,
	COAP_OPTION_CONTENT_FORMAT	= 12,
	COAP_OPTION_MAX_AGE			= 14,
	COAP_OPTION_URI_QUERY		= 15,
	COAP_OPTION_ACCEPT			= 16,
	COAP_OPTION_TOKEN			= 19,
	COAP_OPTION_LOCATION_QUERY	= 20,
	COAP_OPTION_BLOCK2			= 23,
	COAP_OPTION_BLOCK1			= 27,
	COAP_OPTION_SIZE			= 28,
	COAP_OPTION_PROXY_URI		= 35,
//	128 =  	(Reserved)
//	132 =  	(Reserved)
//	136 =  	(Reserved)
} sn_coap_option_numbers_e;

/* Enumeration for CoAP Content Format codes */
typedef enum sn_coap_content_format_
{
	COAP_CT_NONE				= -1,
    COAP_CT_TEXT_PLAIN          = 0,
    COAP_CT_LINK_FORMAT			= 40,
    COAP_CT_XML			        = 41,
    COAP_CT_OCTET_STREAM		= 42,
    COAP_CT_EXI			        = 47,
    COAP_CT_JSON			    = 50,
} sn_coap_content_format_e;

/* Enumeration for CoAP status, used in CoAP Header */
typedef enum sn_coap_status_
{
    COAP_STATUS_OK                             = 0, /* Default value is OK */
    COAP_STATUS_PARSER_ERROR_IN_HEADER         = 1, /* CoAP will send Reset message to invalid message sender */
    COAP_STATUS_PARSER_DUPLICATED_MSG          = 2, /* CoAP will send Acknowledgement message to duplicated message sender */
    COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING = 3, /* User will get whole message after all message blocks received.
                                                       User must release messages with this status. */
    COAP_STATUS_PARSER_BLOCKWISE_ACK           = 4, /* Acknowledgement for sent Blockwise message received */
    COAP_STATUS_PARSER_BLOCKWISE_MSG_REJECTED  = 5, /* Blockwise message received but not supported by compiling switch */
    COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED  = 6  /* Blockwise message fully received and returned to app. */
    												/* User must take care of releasing whole payload of the blockwise messages */
} sn_coap_status_e;


/* * * * * * * * * * * * * */
/* * * * STRUCTURES  * * * */
/* * * * * * * * * * * * * */

/* Structure for CoAP Options */
typedef struct sn_coap_options_list_
{

	/* If-Match */
	/* If-None-Match */
	/* Size */

    uint8_t     max_age_len;
    uint8_t    *max_age_ptr;        /* Must be set to NULL if not used */

    uint16_t    proxy_uri_len;
    uint8_t    *proxy_uri_ptr;      /* Must be set to NULL if not used */

    uint8_t     etag_len;
    uint8_t    *etag_ptr;           /* Must be set to NULL if not used */

    uint16_t    uri_host_len;
    uint8_t    *uri_host_ptr;       /* Must be set to NULL if not used */

    uint16_t    location_path_len;
    uint8_t    *location_path_ptr;  /* Must be set to NULL if not used */

    uint8_t     uri_port_len;
    uint8_t    *uri_port_ptr;       /* Must be set to NULL if not used */

    uint16_t    location_query_len;
    uint8_t    *location_query_ptr; /* Must be set to NULL if not used */

    uint8_t     observe;
    uint8_t     observe_len;
    uint8_t    *observe_ptr;        /* Must be set to NULL if not used */

    uint8_t     accept_len;   		/* Must be set to zero if not used */
    uint8_t     *accept_ptr;   		/* Must be set to NULL if not used */

    uint16_t    uri_query_len;
    uint8_t    *uri_query_ptr;      /* Must be set to NULL if not used */

    uint8_t     block1_len;         /* Not for User */
    uint8_t    *block1_ptr;         /* Not for User */

    uint8_t     block2_len;         /* Not for User */
    uint8_t    *block2_ptr;         /* Not for User */
} sn_coap_options_list_s;

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
/* !!! Main CoAP message struct !!! */
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
typedef struct sn_coap_hdr_
{
    sn_coap_status_e        coap_status;        /* Used for telling to User special cases when parsing message */

    /* * * * * * * * * * * */
    /* * * * Header  * * * */
    /* * * * * * * * * * * */

    sn_coap_msg_type_e      msg_type;           /* Confirmable, Non-Confirmable, Acknowledgement or Reset */
    sn_coap_msg_code_e      msg_code;           /* Empty: 0; Requests: 1-31; Responses: 64-191 */
    uint16_t				msg_id;				/* Message ID. Parser sets parsed message ID, builder sets message ID of built coap message */

    /* * * * * * * * * * * */
    /* * * * Options * * * */
    /* * * * * * * * * * * */

    /* Here are most often used Options */

    uint16_t                uri_path_len;       /* Must be set to zero if not used */
    uint8_t                *uri_path_ptr;       /* Must be set to NULL if not used. E.g: temp1/temp2 */

    uint8_t                 token_len;          /* Must be set to zero if not used */
    uint8_t                *token_ptr;          /* Must be set to NULL if not used */

    /* todo: COAP12 - content type ptr as a content_type_e */
    uint8_t                 content_type_len;   /* Must be set to zero if not used */
    uint8_t                *content_type_ptr;   /* Must be set to NULL if not used */

    /* Here are not so often used Options */
    sn_coap_options_list_s *options_list_ptr;   /* Must be set to NULL if not used */

    /* * * * * * * * * * * */
    /* * * * Payload * * * */
    /* * * * * * * * * * * */

    uint16_t                payload_len;        /* Must be set to zero if not used */
    uint8_t		           *payload_ptr;        /* Must be set to NULL if not used */
} sn_coap_hdr_s;

/* * * * * * * * * * * * * * * * * * * * * * */
/* * * * EXTERNAL FUNCTION PROTOTYPES  * * * */
/* * * * * * * * * * * * * * * * * * * * * * */

extern void           sn_coap_builder_and_parser_init(void* (*used_malloc_func_ptr)(uint16_t), void (*used_free_func_ptr)(void*));
extern sn_coap_hdr_s *sn_coap_parser(uint16_t packet_data_len, uint8_t *packet_data_ptr, coap_version_e *coap_version_ptr);
extern int16_t        sn_coap_builder(uint8_t *dst_packet_data_ptr, sn_coap_hdr_s *src_coap_msg_ptr);
extern uint16_t       sn_coap_builder_calc_needed_packet_data_size(sn_coap_hdr_s *src_coap_msg_ptr);
extern void           sn_coap_builder_release_allocated_send_msg_mem(sn_nsdl_transmit_s *freed_send_msg_ptr);
extern sn_coap_hdr_s *sn_coap_build_response(sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code);
extern void           sn_coap_parser_release_allocated_coap_msg_mem(sn_coap_hdr_s *freed_coap_msg_ptr);
extern void 		  sn_coap_packet_debug(sn_coap_hdr_s *coap_packet_ptr);

#endif /* SN_COAP_HEADER_H_ */
