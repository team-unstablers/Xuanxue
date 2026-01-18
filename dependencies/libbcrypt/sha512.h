#ifndef SHA512_H_
#define SHA512_H_

#include <stdint.h>

/* sum must have space for at least 512 bits. */
void bcrypt_sha512_calc(const void *in, unsigned long len, char *sum);

/* Public API for bcrypt_pbkdf */
typedef struct {
    uint64_t len;
    uint64_t h[8];
    uint8_t buf[128];
} SHA512_CTX;

void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const void *data, unsigned long len);
void SHA512_Final(uint8_t *digest, SHA512_CTX *ctx);

#endif
