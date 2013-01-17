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

#define EDTLS_SUCCESS 0
#define EDTLS_FAILURE -1
#define SN_EDTLS_VERSION_NOT_SUPPORTED -2

#define SN_EDTLS_FINISH_DATA_LENGTH 28

#define FRAME_LABEL_LENGTH 1
#define SESSION_LIFETIME_LENGTH 8
#define COMPLETE_LENGTH 12
#define FINISHED_LENGTH 12

/* Bit masks for record header */
/*MSB*/
#define FRAME_MASK = 0x0300
#define RECORD_LAYER_FRAME 0
#define EDTLS_COMPRESSED_FRAME 0x0100
#define EDTLS_CIPHER_TEXT_FRAME 0x0200
#define EDTLS_VERSION 0x2000
/*LSB*/
#define EDTLS_PROTOCOL_MASK 0x0003
#define EDTLS_HANDSHAKE_PROTOCOL 0
#define EDTLS_ALERT_PROTOCOL 0x0001
#define EDTLS_APPLICATION_DATA_PROTOCOL 0x0002
#define EDTLS_NETWORK_MANAGEMENT_PROTOCOL 0x0003

#define EDTLS_LENGTH_FIELD_PRESENT 0x0004
#define EDTLS_SEQ_NUMBER_PRESENT 0x0008
#define EDTLS_SESSION_ID_PRESENT 0x0010

#define FRAMELABEL 0
#define HELLO_REQUEST 1
#define CLIENT_HELLO 2
#define SERVER_HELLO 3
#define CERTIFICATE 4
#define KEY_EXHANGE 5
#define SIGNATURE 6
#define FINISHED 7
#define COMPLETE 8
#define SESSION_LIFETIME 9

#define EDTLS_PING_REQUEST 0
#define EDTLS_PING_RESPONSE 1
#define EDTLS_RELAY 2
#define EDTLS_NWK_UPDATE 3
#define EDTLS_NWK_CONFIRM 4
#define EDTLS_NWK_REQUEST 5
#define EDTLS_ADDRESS_UPDATE 6

#define	EDTLS_ALERT_CLOSE_NOTIFY 0
#define	EDTLS_ALERT_UNEXPECTED_MESSAGE 10
#define	EDTLS_ALERT_BAD_RECORD_MAC 20
#define	EDTLS_ALERT_RECORD_OVERFLOW 22
#define	EDTLS_ALERT_DECOMPRESSION_FAILURE 30
#define	EDTLS_ALERT_HANDSHAKE_FAILURE 40
#define	EDTLS_ALERT_BAD_CERTIFICATE 42
#define	EDTLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define EDTLS_ALERT_CERTIFICATE_REVOKED 44
#define	EDTLS_ALERT_CERTIFICATE_EXPIRED 45
#define	EDTLS_ALERT_CERTIFICATE_UNKNOWN 46
#define	EDTLS_ALERT_ILLEAGAL_PARAMETER 47
#define	EDTLS_ALERT_UNKNOWN_CA 48
#define	EDTLS_ALERT_ACCESS_DENIED 49
#define	EDTLS_ALERT_DECODE_ERROR 50
#define	EDTLS_ALERT_DECRYPT_ERROR 51
#define	EDTLS_ALERT_PROTOCOL_VERSION 70
#define	EDTLS_ALERT_INSUFFICIENT_SECURITY 71
#define	EDTLS_ALERT_ILLEAGAL_COOKIE 72
#define	EDTLS_ALERT_INTERNAL_ERROR 80
#define	EDTLS_ALERT_NO_RENEGOTIATION 100
#define	EDTLS_ALERT_UNSUPPORTED_EXTENSION 110
#define	EDTLS_ALERT_RETRANSMISSION_EXPIRED 120
#define	EDTLS_ALERT_RETRANSMISSION_EXCEEDED 121
#define	EDTLS_ALERT_INVALID_KEYID_EXTENSION 130

#define WARNING 1
#define FATAL 2

#define EXTENSIONS_MASK 0x0F
#define SESSION_ID_MASK 0x10
#define CERT_REQ_MASK 	0x80

#define SHALIB_RING_BUFFER_SIZE 64

#ifdef ECC
#define NUMBER_OF_SUPPORTED_CIPHER_SUITES 1 // 2
#define SN_EDTLS_CLIENT_HELLO_LENGTH 41 //45
#else
#define NUMBER_OF_SUPPORTED_CIPHER_SUITES 1
#define SN_EDTLS_CLIENT_HELLO_LENGTH 41
#endif


#define EDTLS_CONNECTION_OK 1
#define EDTLS_CONNECTION_CLOSED 2
#define EDTLS_CONNECTION_FAILED 3
#define EDTLS_ECC_CALCULATING 4


/**************/
/* Structures */
/**************/

typedef struct sn_edtls_address_
{
	uint16_t port;
	uint8_t address[16];
	uint8_t socket;
}sn_edtls_address_t;

typedef struct sn_edtls_record_
{
	uint16_t flags;
	uint16_t length; 			/* optional, indicated by flags */
	uint8_t sessionID[4]; 		/* optional, indicated by flags */
	uint8_t seq_nro[8]; 		/* optional, indicated by flags */
} sn_edtls_record_t;


typedef struct sn_edtls_data_buffer_
{
	uint16_t len;
	uint8_t *buff;
}sn_edtls_data_buffer_t;

typedef struct sn_edtls_alert_
{
	uint8_t alert_level;
	uint8_t alert_desctiption;
}sn_edtls_alert_t;

typedef struct sn_edtls_aes_data_
{
	uint8_t *data_ptr;
	uint16_t length;
	uint8_t keylen;
	uint8_t *key;
}sn_edtls_aes_data_t;



/**********************/
/* from other headers */
/**********************/

#define EDTLS_HANSHAKE_HASH 0x08
#define TLS_SERVER_MODE 0x10

#define CLIENT_HELLO_PTR 0
#define SERVER_HELLO_PTR 32

#define CLIENT_WRITE_KEY 	0
#define SERVER_WRITE_KEY 	16
#define CLIENT_IV 			32
#define SERVER_IV 			36

typedef enum
{
	EDTLS_INIT = 0,
	EDTLS_DISCONNECTED,
	EDTLS_CLIENT_HELLO_SENT,
	EDTLS_SERVER_HELLO_RECEIVED,
	EDTLS_ECC_KEY_CALCULATING,
	EDTLS_ECC_KEY_READY,
	EDTLS_VERIFY_CALCULATING,
	EDTLS_START_SHDE,
	EDTLS_SHDE_CALCULATE_SIGNATURE,
	EDTLS_SHDE_SIGNATURE_READY,
	EDTLS_FINISHED_RECEIVED,
	EDTLS_FINISHED_SENT,
	EDTLS_CONNECTED,
} sec_state_machine_t;

typedef enum
{
	CHIPHER_NONE = 0,
	CHIPHER_PSK,
	CHIPHER_ECC
} tls_chipher_mode_t;

#ifdef ECC
typedef struct
{
	EllipticPoint cert_pub_key;		// 80 bytes
	uint8_t client_public_key[64];	// Pk Client: client_public_key[0-31] X point, client_public_key[32-63] y point remember change byte order
	uint8_t server_public_key[64]; 	// Pk server server_public_key[0-31] X point, server_public_key[32-63] y point remember change byte order
	uint8_t pre_secret_mat[32];  	// Client Pk server * k*curve and server Pk client*k*curve only x point
	ECDSASignature *sgnt;
	MPint private_key;
	uint8_t hashed_messages;
}tls_ecc_heap_t;
#endif

typedef struct
{
#ifdef ECC
	tls_ecc_heap_t * ecc_heap;
#endif
	uint8_t master_secret[48]; 	//len 48 bytes
	uint8_t temp_buf[64];				// len 64 bytes
	uint8_t verify[16];				// len 16 bytes
	uint8_t tls_hello_random[64];
	uint8_t hash_buf[32];			//32 bytes
	uint8_t prf_buf[64];
	uint16_t tls_handshake_h_len;
	tls_chipher_mode_t tls_chipher_mode;
	sha256_temp_t sha256_hash_temp;

}tls_heap_t;

typedef struct tls_session_t
{
	uint8_t key_expansion[64];
	uint8_t id_length;
//	uint8_t tls_session_id[32];
	uint8_t tls_session_id[4];
	uint8_t tls_nonce_explit[8];
	tls_heap_t *tls_heap;
} tls_session_t;

typedef struct sec_suite_t
{
#ifdef PANA
	pana_session_t *pana_session;
#endif
	tls_session_t tls_session;
	sec_state_machine_t state;
	uint16_t timer;
	uint8_t socket_id;
	//nwk_interface_id if_index;
	uint16_t setups;
	uint8_t supported_chipher_suites;
	uint8_t session_address[16];
	uint16_t session_port;
//	struct sec_suite_t			*prev;
//	struct sec_suite_t			*next;
} sec_suite_t;


extern void sn_edtls_destroy(void);
extern int8_t sn_edtls_libraray_initialize(void);
extern int16_t sn_edtls_connect(sn_edtls_address_t *address);
extern int8_t sn_edtls_disconnect(int16_t session_id);
extern int16_t sn_edtls_parse_data(int16_t session_id, sn_edtls_data_buffer_t *message_buffer_ptr);
extern int8_t sn_edtls_write_data(int16_t session_id, sn_edtls_data_buffer_t *message_buffer_ptr);
extern void edtls_pre_shared_key_set(uint8_t *key, uint16_t key_id);
extern void sn_edtls_exec(uint32_t system_time);


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

/**
 * \fn extern uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *address_ptr)
 * \brief Tx callback for eDTLS library for sending messages
 * \param *data_ptr Pointer to eDTLS data to be send
 * \param data_len eDTLS data length
 * \param *address_ptr Pointer to structure that contains source port, source address and UDP socket id
 * \return
 */
extern uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *address_ptr);

/**
 * \fn extern uint8_t edtls_random()
 * \brief Random function to get 8-bit randomized numbers
  * \return 8-bit random integer
 */
extern uint8_t edtls_random();

/**
 * \fn extern void edtls_registration_status(uint8_t status, int16_t session_id)
 * \brief Callback function for eDTLS library for passing eDTLS connection status
 * \param status
 */
extern void edtls_registration_status(uint8_t status, int16_t session_id);

/**
 * \fn extern void aes_encrypt(unsigned char *block_ptr, unsigned char *key_ptr)
 * \brief
 * \param
 * \return
 */
extern void	aes_encrypt(unsigned char *block_ptr, unsigned char *key_ptr);


#endif /* SN_EDTLS_LIB_H_ */
