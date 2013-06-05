#ifndef SN_AES
#define SN_AES

void aes_encrypt(unsigned char *plaintext_ptr, unsigned char *aes_key_ptr);
void aes_decrypt(unsigned char *ciphertext_ptr, unsigned char *aes_key_ptr);

#endif
