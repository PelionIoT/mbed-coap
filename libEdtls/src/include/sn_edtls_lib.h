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

#define ALERT_MESSAGE_LENGTH 2
#define SN_EDTLS_FINISH_DATA_LENGTH 28

#define EDTLS_PROTOCOL_MASK 0x03
#define EDTLS_LENGTH_FIELD_PRESENT 0x04
#define EDTLS_SESSION_ID_PRESENT 0x10
#define EDTLS_SEQ_NUMBER_PRESENT 0x08
#define EDTLS_VERSION_1 0x20

#define EDTLS_HANDSHAKE_PROTOCOL 0x00
#define EDTLS_ALERT_PROTOCOL 0x01
#define EDTLS_APPLICATION_DATA_PROTOCOL 0x02

#define FRAMELABEL 0
#define HELLO_REQUEST 1
#define CLIENT_HELLO 2
#define SERVER_HELLO 3
#define CERTIFICATE 4
#define KEY_EXHANGE 5
#define SIGNATURE 6
#define FINISHED 7

#define	CLOSE_NOTIFY 0
#define	UNEXPECTED_MESSAGE 10
#define	BAD_RECORD_MAC 20
#define	RECORD_OVERFLOW 22
#define	DECOMPRESSION_FAILURE 30
#define	HANDSHAKE_FAILURE 40
#define	BAD_CERTIFICATE 42
#define	UNSUPPORTED_CERTIFICATE 43
#define CERTIFICATE_REVOKED 44
#define	CERTIFICATE_EXPIRED 45
#define	CERTIFICATE_UNKNOWN 46
#define	ILLEAGAL_PARAMETER 47
#define	UNKNOWN_CA 48
#define	ACCESS_DENIED 49
#define	DECODE_ERROR 50
#define	DECRYPT_ERROR 51
#define	PROTOCOL_VERSION 70
#define	INSUFFICIENT_SECURITY 71
#define	ILLEAGAL_COOKIE 72
#define	INTERNAL_ERROR 80
#define	NO_RENEGOTIATION 100
#define	UNSUPPORTED_EXTENSION 110
#define	RETRANSMISSION_EXPIRED 120
#define	RETRANSMISSION_EXCEEDED 121
#define	INVALID_KEYID_EXTENSION 130

#define WARNING 1
#define FATAL 2

#define EXTENSIONS_MASK 0x0F
#define SESSION_IF_MASK 0x10

#define SHALIB_RING_BUFFER_SIZE 64

#define NUMBER_OF_SUPPORTED_CIPHER_SUITES 1

#define EDTLS_CONNECTION_FAILED 0
#define EDTLS_CONNECTION_OK 1
#define EDTLS_CONNECTION_CLOSED 2

/**************/
/* Structures */
/**************/

typedef struct sn_edtls_address_
{
	uint16_t port;
	uint8_t address[16];
	uint8_t socket;
}sn_edtls_address_t;

typedef struct sn_edtls_plaintext_
{
	uint8_t flags;
	uint8_t protocol;
	uint16_t length; 			/* optional, indicated by flags */
	uint8_t sessionID[4]; 		/* optional, indicated by flags */
	uint8_t seq_nro[8]; 		/* optional, indicated by flags */
} sn_edtls_record_t;


typedef struct sn_edtls_data_buffer_
{
	uint16_t len;
	uint8_t *buff;
	sn_edtls_address_t *address;
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

#define TLS_HANSHAKE_HASH 0x08
#define CLIENT_HELLO_PTR 0
#define SERVER_HELLO_PTR 32

#define CLIENT_WRITE_KEY 	0
#define SERVER_WRITE_KEY 	16
#define CLIENT_IV 			32
#define SERVER_IV 			36

typedef enum
{
	EDTLS_INIT,
	EDTLS_CLIENT_HELLO_SENT,
	EDTLS_SERVER_HELLO_RECEIVED,
	EDTLS_CONNECTED,
	EDTLS_CLOSE_NOTIFY_SENT
} sec_state_machine_t;

typedef enum
{
	CHIPHER_NONE = 0,
	CHIPHER_PSK,
	CHIPHER_ECC
} tls_chipher_mode_t;


typedef struct
{
	#ifdef ECC
	tls_ecc_heap_t * ecc_heap;
#endif
	uint8_t master_secret[48]; 	//len 48 bytes
	uint8_t temp_buf[64];				// len 64 bytes
//	uint8_t verify[16];				// len 16 bytes
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
//	uint16_t timer;
	uint8_t socket_id;
//	nwk_interface_id if_index;
	uint8_t setups;
	uint8_t supported_chipher_suites;
//	uint16_t client_verify_buf_len;
//	uint8_t * client_verify_buf;
	uint8_t session_address[16];
	uint16_t session_port;
//	struct sec_suite_t			*prev;
//	struct sec_suite_t			*next;
} sec_suite_t;


/* Frees all allocated memory */
extern void sn_edtls_destroy(void);

/* eDTLS Library initialization */
extern int8_t sn_edtls_libraray_initialize(void);

/*
 * Starts hadshake to server. Returns unique session ID to be used to identify session
 */
extern int8_t sn_edtls_connect(sn_edtls_address_t *address);

/*
 * Disconnects session
 */
extern int8_t sn_edtls_disconnect(uint8_t session_id);

/*
 * Reads eDTLS data and returns parsed data.
 */
extern int16_t sn_edtls_read_data(uint8_t session_id, sn_edtls_data_buffer_t *return_buffer_ptr);

/*
 * Writes eDTLS data
 */
extern int8_t sn_edtls_write_data(uint8_t session_id, sn_edtls_data_buffer_t *message_buffer);


/* External functions. These should found somewhere in the application */
extern void 	*edtls_malloc(uint16_t);
extern void 	edtls_free(void *);
extern uint8_t 	edtls_tx(uint8_t *, uint16_t, sn_edtls_address_t *);
extern uint8_t 	edtls_random();
extern void 	edtls_registration_status(uint8_t);
extern void		aes_encrypt(unsigned char *block_ptr, unsigned char *key_ptr);

#endif /* SN_EDTLS_LIB_H_ */
