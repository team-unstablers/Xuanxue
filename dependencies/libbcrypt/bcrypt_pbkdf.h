#ifndef BCRYPT_PBKDF_H
#define BCRYPT_PBKDF_H

#include <stdint.h>
#include <stddef.h>

/*
 * bcrypt_pbkdf - Password-Based Key Derivation Function based on bcrypt
 *
 * This is the key derivation function used by OpenSSH for encrypted private keys.
 * It derives key material from a password and salt using bcrypt as the core hash.
 *
 * @param pass      Password bytes
 * @param passlen   Length of password
 * @param salt      Salt bytes
 * @param saltlen   Length of salt
 * @param key       Output buffer for derived key
 * @param keylen    Desired length of derived key
 * @param rounds    Number of rounds (iterations)
 *
 * @return 0 on success, -1 on error
 */
int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt,
                 size_t saltlen, uint8_t *key, size_t keylen, unsigned int rounds);

#endif /* BCRYPT_PBKDF_H */
