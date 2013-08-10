/*
 * sn_edtls_lib.h
 *
 *  Created on: Aug 22, 2012
 *      Author: tero
 */

#ifndef SN_EDTLS_LIB_H_
#define SN_EDTLS_LIB_H_


/***********/
/* Defines */
/***********/
#define EDTLS_MAX_CONNECTIONS	5

#define EDTLS_SUCCESS 0
#define EDTLS_FAILURE -1
#define SN_EDTLS_VERSION_NOT_SUPPORTED -2


#define EDTLS_CONNECTION_OK 1
#define EDTLS_CONNECTION_CLOSED 2
#define EDTLS_CONNECTION_FAILED 3
#define EDTLS_ECC_CALCULATING 4

#define CERTI_CHAIN_MAX_SUP 2

typedef enum sn_edtls_address_type_
{
	SN_EDTLS_ADDRESS_TYPE_NOT_DEFINED 	= 0x00,
    SN_EDTLS_ADDRESS_TYPE_IPV6       	= 0x01,
    SN_EDTLS_ADDRESS_TYPE_IPV4       	= 0x02,
    SN_EDTLS_ADDRESS_TYPE_HOSTNAME   	= 0x03,
    SN_EDTLS_ADDRESS_TYPE_NONE       	= 0xFF
}sn_edtls_address_type_t;

/**************/
/* Structures */
/**************/
typedef struct
{
	uint8_t certificate_owner;
	uint8_t chain_length;
	const uint8_t *certi_chain[CERTI_CHAIN_MAX_SUP];
	uint16_t certi_len[CERTI_CHAIN_MAX_SUP];
	const uint8_t *key_chain[CERTI_CHAIN_MAX_SUP];
	const uint8_t *sub_chain[CERTI_CHAIN_MAX_SUP];
	uint16_t sub_len[CERTI_CHAIN_MAX_SUP];
}edtls_certificate_chain_entry_t;


typedef struct sn_edtls_address_
{
	uint16_t port;
	uint8_t address[16];
	sn_edtls_address_type_t address_type;
	uint8_t socket;
}sn_edtls_address_t;


typedef struct sn_edtls_data_buffer_
{
	uint16_t len;
	uint8_t *buff;
}sn_edtls_data_buffer_t;


extern void sn_edtls_destroy(void);
extern int8_t sn_edtls_libraray_initialize(void);
extern int16_t sn_edtls_connect(sn_edtls_address_t *address, uint8_t (*edtls_tx_cb)(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *address_ptr),
								void (*registration_status_cb)(uint8_t status, int16_t session_id));
extern int8_t sn_edtls_disconnect(int16_t session_id);
extern int16_t sn_edtls_parse_data(int16_t session_id, sn_edtls_data_buffer_t *message_buffer_ptr);
extern int8_t sn_edtls_write_data(int16_t session_id, sn_edtls_data_buffer_t *message_buffer_ptr);
extern void edtls_pre_shared_key_set(uint8_t *key, uint16_t key_id);
extern void sn_edtls_exec(uint32_t system_time);
extern int8_t edtls_cetificate_list_update(edtls_certificate_chain_entry_t *c_chain);

/***********************************************************************/
/* External functions. These should found somewhere in the application */
/***********************************************************************/

/**
 * \fn extern void 	*edtls_malloc(uint16_t size)
 * \brief Memory allocation function for eDTLS library
 * \param size Length of the memory to be allocated
 * \return Returns pointer to allocated memory block, 0 if allocation failed
 */
extern void *edtls_malloc(uint16_t size);

/**
 * \fn extern void 	edtls_free(void *ptr)
 * \brief Free function for eDTLS library
 * \param ptr Pointer to memory block to be free'd
 */
extern void edtls_free(void *ptr);

///**
// * \fn extern uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *address_ptr)
// * \brief Tx callback for eDTLS library for sending messages
// * \param *data_ptr Pointer to eDTLS data to be send
// * \param data_len eDTLS data length
// * \param *address_ptr Pointer to structure that contains source port, source address and UDP socket id
// * \return
// */
//extern uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *address_ptr);

/**
 * \fn extern uint8_t edtls_random()
 * \brief Random function to get 8-bit randomized numbers
  * \return 8-bit random integer
 */
extern uint8_t edtls_random();

///**
// * \fn extern void edtls_registration_status(uint8_t status, int16_t session_id)
// * \brief Callback function for eDTLS library for passing eDTLS connection status
// * \param status
// */
//extern void edtls_registration_status(uint8_t status, int16_t session_id);

/**
 * \fn extern void aes_encrypt(unsigned char *block_ptr, unsigned char *key_ptr)
 * \brief
 * \param
 * \return
 */
extern void	aes_encrypt(unsigned char *block_ptr, unsigned char *key_ptr);


#endif /* SN_EDTLS_LIB_H_ */
