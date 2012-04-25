/**
 * \file sn_coap_header_validity_check_ietf_draft_06.c
 *
 * \brief CoAP Header validity checker
 *
 * Functionality: Checks validity of CoAP Header
 *
 *  Created on: Aug 22, 2011
 *      Author: pekka_ext
 *
 * \note Supports draft-ietf-core-coap-06
 */

/* * * * * * * * * * * * * * */
/* * * * INCLUDE FILES * * * */
/* * * * * * * * * * * * * * */

#include "pl_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header_ietf_draft_09.h"
#include "sn_coap_protocol_ietf_draft_09.h"

/* * * * * * * * * * * * * * * * * * * * */
/* * * * LOCAL FUNCTION PROTOTYPES * * * */
/* * * * * * * * * * * * * * * * * * * * */

static int8_t sn_coap_header_validity_check_coap_version(uint8_t value);
static int8_t sn_coap_header_validity_check_message_type(uint8_t value);
static int8_t sn_coap_header_validity_check_message_code(uint8_t value);

/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC int8_t sn_coap_header_validity_check(sn_coap_hdr_s *src_coap_msg_ptr, coap_version_e coap_version)
 *
 * \brief Checks validity of given Header
 *
 * \param *src_coap_msg_ptr is source for building Packet data
 * \param coap_version is version of used CoAP specification
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
int8_t sn_coap_header_validity_check(sn_coap_hdr_s *src_coap_msg_ptr, coap_version_e coap_version)
{
    /* * Check validity of CoAP Version * */

    int8_t ret_status = sn_coap_header_validity_check_coap_version(coap_version);

    if (ret_status != 0)
    {
        /* Return error code */
        return -1;
    }

    /* * Check validity of Message type * */

    ret_status = sn_coap_header_validity_check_message_type(src_coap_msg_ptr->msg_type);

    if (ret_status != 0)
    {
        /* Return error code */
        return -1;
    }

    /* * Check validity of Message code * */

    ret_status = sn_coap_header_validity_check_message_code(src_coap_msg_ptr->msg_code);

    if (ret_status != 0)
    {
        /* Return error code */
        return -1;
    }

    /* Great success */
    return 0;
}

/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC int8_t sn_coap_header_validity_check_options_count(uint8_t value)
 *
 * \brief Checks validity of given Options count
 *
 * \param value is value to be checked
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
int8_t sn_coap_header_validity_check_options_count(uint8_t value)
{
    /* Check range of Options count */
    if (value <= COAP_OPTIONS_MAXIMUM_COUNT)
    {
        /* Ok case */
        return 0;
    }
    else
    {
        /* Failed case */
        return -1;
    }
}


/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC int8_t sn_coap_builder_options_check_validity_option_len(uint16_t value)
 *
 * \brief Checks validity of given Option length
 *
 * \param value is value to be checked
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
int8_t sn_coap_builder_options_check_validity_option_len(uint16_t value)
{
    /* Check range of Option length */
    if (value <= COAP_OPTIONS_OPTION_MAXIMUM_LENGTH)
    {
        /* Ok case */
        return 0;
    }
    else
    {
        /* Failed case */
        return -1;
    }
}

/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC static int8_t sn_coap_header_validity_check_coap_version(uint8_t value)
 *
 * \brief Checks validity of given CoAP Version
 *
 * \param value is value to be checked
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
static int8_t sn_coap_header_validity_check_coap_version(uint8_t value)
{
    /* Check validity of CoAP Version */
    switch (value)
    {
        /* Ok cases */
        case COAP_VERSION_1:
            return 0;

        /* Failed case */
        default:
            return -1;
    }
}

/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC static int8_t sn_coap_header_validity_check_message_type(uint8_t value)
 *
 * \brief Checks validity of given Message type
 *
 * \param value is value to be checked
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
static int8_t sn_coap_header_validity_check_message_type(uint8_t value)
{
    /* Check validity of Message type */
    switch (value)
    {
        /* Ok cases */
        case COAP_MSG_TYPE_CONFIRMABLE:
        case COAP_MSG_TYPE_NON_CONFIRMABLE:
        case COAP_MSG_TYPE_ACKNOWLEDGEMENT:
        case COAP_MSG_TYPE_RESET:
            return 0;

        /* Failed case */
        default:
            return -1;
    }
}

/**
 * \fn SN_MEM_ATTR_COAP_VALID_CHECK_FUNC static int8_t sn_coap_header_validity_check_message_code(uint8_t value)
 *
 * \brief Checks validity of given Message code
 *
 * \param value is value to be checked
 *
 * \return Return value is status of validity check. In ok cases 0 and in
 *         failure cases -1
 */
SN_MEM_ATTR_COAP_VALID_CHECK_FUNC
static int8_t sn_coap_header_validity_check_message_code(uint8_t value)
{
    /* Check validity of Message code */
    switch (value)
    {
        /* Ok cases */

        case COAP_MSG_CODE_EMPTY:

        case COAP_MSG_CODE_REQUEST_GET:
        case COAP_MSG_CODE_REQUEST_POST:
        case COAP_MSG_CODE_REQUEST_PUT:
        case COAP_MSG_CODE_REQUEST_DELETE:

        case COAP_MSG_CODE_RESPONSE_CREATED:
        case COAP_MSG_CODE_RESPONSE_DELETED:
        case COAP_MSG_CODE_RESPONSE_VALID:
        case COAP_MSG_CODE_RESPONSE_CHANGED:
        case COAP_MSG_CODE_RESPONSE_CONTENT:
        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_MEDIA_TYPE:
        case COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR:
        case COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED:
        case COAP_MSG_CODE_RESPONSE_BAD_GATEWAY:
        case COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE:
        case COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT:
        case COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED:

            return 0;

        /* Failed case */
        default:
            return -1;
    }
}
