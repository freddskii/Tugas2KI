#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16

#define AES_OK                 0
#define AES_ERR_PARAM         -1
#define AES_ERR_KEY_LENGTH    -2

typedef struct
{
   int nr;            /* number of rounds: 10, 12, or 14 */
   uint32_t ek[60];   /* encryption key schedule */
   uint32_t dk[60];   /* decryption key schedule */
} AesContext;

/* keyLen must be 16, 24, or 32 bytes */
int  aesInit(AesContext *context, const uint8_t *key, size_t keyLen);
void aesEncryptBlock(const AesContext *context, const uint8_t *input, uint8_t *output);
void aesDecryptBlock(const AesContext *context, const uint8_t *input, uint8_t *output);
void aesDeinit(AesContext *context);

#endif
