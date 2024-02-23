#ifndef FWB_CRYPTO_H
#define FWB_CRYPTO_H

#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct signature {
  uint8_t *bytes;
  size_t len;
};

typedef enum { PUBLIC_KEY, PRIVATE_KEY } key_type_t;

EVP_PKEY *fwb_load_key(const char *path, key_type_t type);

struct signature fwb_sign(const void *data, unsigned len, EVP_PKEY *key);
bool fwb_verify(const void *data, unsigned len, EVP_PKEY *key, struct signature sig);


struct hash_block
{
  uint8_t md5[MD5_DIGEST_LENGTH];
  uint8_t sha256[SHA256_DIGEST_LENGTH];
};

struct hash_context;

struct hash_context *fwb_hash_context_new(void);
void fwb_hash_context_free(struct hash_context *hc);

bool fwb_hash_update(const uint8_t *data, unsigned len, struct hash_context *hc);
bool fwb_hash_final(struct hash_context *hc, struct hash_block *hb);

#ifdef __cplusplus
}
#endif

#endif
