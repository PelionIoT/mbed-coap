/**
 * \file sn_coap_protocol_ietf_draft_12.h
 *
 * \brief Header file for CoAP Protocol part
 *
 *  Created on: Jun 30, 2011
 *      Author: tero
 *
 * \note Supports draft-ietf-core-coap-12
 */

#ifndef SN_COAP_PROTOCOL_IETF_DRAFT_09_H_
#define SN_COAP_PROTOCOL_IETF_DRAFT_09_H_

/* * * * * * * * * * * */
/* * * * DEFINES * * * */
/* * * * * * * * * * * */

/* CoAP Resending defines */
//#define MAX_RETRANSMIT          3   /* Maximum resending count, value is specified in IETF CoAP specification */
#define RESPONSE_TIMEOUT        2   /* Initial resending timeout as seconds, value is specified in IETF CoAP specification */
#define RESPONSE_RANDOM_FACTOR  1   /* Resending random factor, value is specified in IETF CoAP specification */

/* * * * * * * * * * * * * * */
/* * * * ENUMERATIONS  * * * */
/* * * * * * * * * * * * * * */

/* * * * * * * * * * * * * */
/* * * * STRUCTURES  * * * */
/* * * * * * * * * * * * * */

/* Structure which is stored to Linked list for message sending purposes */
typedef struct coap_send_msg_
{
    uint8_t             resending_counter;  /* Tells how many times message is still tried to resend */
    uint32_t            resending_time;     /* Tells next resending time */

    sn_nsdl_transmit_s *send_msg_ptr;
} coap_send_msg_s;

/* Structure which is stored to Linked list for message acknowledgement purposes */
typedef struct coap_ack_info_
{
    uint32_t            timestamp; /* Tells when duplication information is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            msg_id;

    uint8_t             token_len;
    uint8_t            *token_ptr;
} coap_ack_info_s;

/* Structure which is stored to Linked list for message duplication detection purposes */
typedef struct coap_duplication_info_
{
    uint32_t            timestamp; /* Tells when duplication information is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            msg_id;
} coap_duplication_info_s;

/* Structure which is stored to Linked list for blockwise messages sending purposes */
typedef struct coap_blockwise_msg_
{
    uint32_t            timestamp;  /* Tells when Blockwise message is stored to Linked list */

    sn_coap_hdr_s		*coap_msg_ptr;
} coap_blockwise_msg_s;

/* Structure which is stored to Linked list for blockwise messages receiving purposes */
typedef struct coap_blockwise_payload_
{
    uint32_t            timestamp; /* Tells when Payload is stored to Linked list */

    uint8_t             addr_len;
    uint8_t            *addr_ptr;
    uint16_t            port;

    uint16_t            payload_len;
    uint8_t            *payload_ptr;
} coap_blockwise_payload_s;


#endif /* SN_COAP_PROTOCOL_IETF_DRAFT_09_H_ */
