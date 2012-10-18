#ifndef TI_AES
#define TI_AES

void aes_encrypt(unsigned char *state, unsigned char *key);
void aes_decrypt(unsigned char *state, unsigned char *key);

#endif