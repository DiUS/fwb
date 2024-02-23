#include "fwbcrypto.h"
#include <stdlib.h>
#include <stdio.h>

EVP_PKEY *fwb_load_key(const char *path, key_type_t type)
{
  EVP_PKEY *key = NULL;
  FILE *fp = fopen(path, "r");
  if (!fp)
    return NULL;
  if (type == PRIVATE_KEY)
    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  else
    key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);
  return key;
}


struct signature fwb_sign(const void *data, unsigned len, EVP_PKEY *key)
{
  struct signature sig = { NULL, 0 };

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx)
    goto err;
 
 if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key) != 1)
   goto err;

 if (EVP_DigestSignUpdate(md_ctx, data, len) != 1)
   goto err;

 if (EVP_DigestSignFinal(md_ctx, NULL, &sig.len) != 1)
   goto err;
 sig.bytes = malloc(sig.len);
 if (!sig.bytes)
   goto err;

 if (EVP_DigestSignFinal(md_ctx, sig.bytes, &sig.len) != 1)
   goto err;

 EVP_MD_CTX_free(md_ctx);

 return sig;

err:
  if (md_ctx)
    EVP_MD_CTX_free(md_ctx);

  if (sig.bytes)
    free(sig.bytes);

  sig.bytes = NULL;
  sig.len = 0;

  return sig;
}


bool fwb_verify(const void *data, unsigned len, EVP_PKEY *key, struct signature sig)
{
  bool ret = false;
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

  if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, key) != 1)
    goto out;

  if (EVP_DigestVerifyUpdate(md_ctx, data, len) != 1)
    goto out;

  if (EVP_DigestVerifyFinal(md_ctx, sig.bytes, sig.len) == 1)
    ret = true;

out:
  EVP_MD_CTX_free(md_ctx);
  return ret;
}


struct hash_context
{
  EVP_MD_CTX *md5;
  EVP_MD_CTX *sha256;
};


struct hash_context *fwb_hash_context_new(void)
{
  struct hash_context *hc = malloc(sizeof(struct hash_context));
  if (!hc)
    goto err;
  hc->md5 = EVP_MD_CTX_new();
  hc->sha256 = EVP_MD_CTX_new();
  if (!hc->md5 || !hc->sha256)
    goto err;

  if (EVP_DigestInit_ex(hc->md5, EVP_md5(), NULL) != 1)
    goto err;
  if (EVP_DigestInit_ex(hc->sha256, EVP_sha256(), NULL) != 1)
    goto err;

  return hc;

err:
  if (hc && hc->md5)
    EVP_MD_CTX_free(hc->md5);
  if (hc && hc->sha256)
    EVP_MD_CTX_free(hc->sha256);
  if (hc)
    free(hc);
  return NULL;
}


void fwb_hash_context_free(struct hash_context *hc)
{
  if (hc && hc->md5)
    EVP_MD_CTX_free(hc->md5);
  if (hc && hc->sha256)
    EVP_MD_CTX_free(hc->sha256);
  free(hc);
}


bool fwb_hash_update(const uint8_t *data, unsigned len, struct hash_context *hc)
{
  if (EVP_DigestUpdate(hc->md5, data, len) != 1)
    return false;
  if (EVP_DigestUpdate(hc->sha256, data, len) != 1)
    return false;
  return true;
}


bool fwb_hash_final(struct hash_context *hc, struct hash_block *hb)
{
  unsigned len = sizeof(hb->md5);
  if (EVP_DigestFinal_ex(hc->md5, hb->md5, &len) != 1)
    return false;
  len = sizeof(hb->sha256);
  if (EVP_DigestFinal_ex(hc->sha256, hb->sha256, &len) != 1)
    return false;
  return true;
}
