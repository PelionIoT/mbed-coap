/*
 * SHALIB.h
 *
 *  Created on: Nov 29, 2010
 *      Author: petri
 */

#ifndef SHALIB_H_
#define SHALIB_H_



#define SHALIB_RING_BUFFER_SIZE 64

typedef struct{
uint8_t *secret;
uint16_t len;
uint8_t label[25]; //25
uint8_t lablen;
uint8_t *seed; //128
uint8_t seedlen;
uint8_t *buffer;
}prf_sec_param_t;

typedef struct{
uint8_t *payload;
uint8_t payload_len;
uint8_t *buffer;
}sha256_param_t;

typedef struct{
uint8_t  m_Data[SHALIB_RING_BUFFER_SIZE];
uint8_t	 m_Read;
uint8_t  m_Write;
uint8_t  m_ReadCount;
uint16_t SHALIB_pushed_bytes;
uint8_t	SHALIB_buffered_bytes;
uint32_t areg_temps[8];
}sha256_temp_t;

// Cumulative static version using a static ring buffer object
//=============================================================================
void SHALIB_init_sha256(void);									// Call this first...
void SHALIB_push_data_sha256(uint8_t *data,uint16_t len);		// ... add data ...
void SHALIB_finish_sha256(uint8_t *buffer, uint8_t len);		// ... get the sha256 digest.

// Use these for cumulativec HMAC
void SHALIB_presecret_set(uint8_t operation);
void SHALIB_init_HMAC(void);		// Call this first...
void SHALIB_finish_HMAC(uint8_t *buffer, uint8_t len); // ... get the HMAC digest.
void sha_resume_regs(sha256_temp_t *ptr);
void sha_save_regs(sha256_temp_t *ptr);

//For MLE HASH calculation
void SHALIB_SHA256_HASH(sha256_param_t * ptr);

void SHALIB_secret_set(uint8_t *secret, uint8_t len);
prf_sec_param_t * shalib_prf_param_get(void);
uint8_t shalib_prf_calc(void);

#endif /* SHALIB_H_ */
