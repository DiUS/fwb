#include "fwbcrypto.h"
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <map>
#include <string>

typedef std::map<std::string, std::string> name2filename;


static void note_data_block(name2filename &map, char *arg)
{
  const char *name = strtok(arg, ":");
  const char *filename = strtok(NULL, ":");
  map[name] = filename;
}


static void error(const char *msg)
{
  fprintf(stderr, "Error: %s\n", msg);
  exit(1);
}


static void hwrite(struct hash_context *hc, const void *data, unsigned len, FILE *fp)
{
  if (!fwb_hash_update((const uint8_t *)data, len, hc))
    error("hash update failed");
  fwrite(data, len, 1, fp);
}


static void append_data_block(const std::string &name, const std::string &fname, struct hash_context *hc, FILE *fp)
{
  char namebuf[16];
  strncpy(namebuf, name.c_str(), sizeof(namebuf));
  hwrite(hc, namebuf, sizeof(namebuf), fp); // name

  int fd = open(fname.c_str(), O_RDONLY | O_LARGEFILE);
  if (fd < 0)
  {
    fprintf(stderr, "Error: unable to open %s\n", fname.c_str());
    exit(1);
  }

  uint64_t sz = lseek64(fd, 0, SEEK_END);
  lseek64(fd, 0, SEEK_SET);
  // TODO: ensure little-endian format
  hwrite(hc, &sz, sizeof(sz), fp); // data block length

  uint8_t block[512];
  size_t n;
  uint64_t written = 0;
  while ((n = read(fd, block, sizeof(block))) > 0)
  {
    hwrite(hc, block, n, fp); // data
    written += n;
  }
  if (n < 0)
  {
    fprintf(stderr, "Error: read error on '%s': %s\n",
      fname.c_str(), strerror(errno));
    exit(1);
  }
  if (written != sz)
  {
    fprintf(stderr, "Error: file '%s' changed size\n", fname.c_str());
    exit(1);
  }

  close(fd);
}


static void help()
{
  fprintf(stderr,
  "fwbcreate -k <privatekey> -K <keyid> -o <outfile.fwb> -d <name:/path/to/source.img> [-d ...]\n"
  "  Create firmware bundle and sign it.\n"
  "\n"
  "Examples:\n"
  "  Create bundle with boot & root parts, signed with 'key1':\n"
  "    fwbcreate -k key1.key -K key1 -o upgrade.fwb -d boot:boot.img -d root:rootfs.ext2\n"
  "\n"
  );
}


int main(int argc, char *argv[])
{
  const char *outfile = NULL;
  const char *keyfile = NULL;
  const char *keyid = NULL;
  name2filename data_blocks;
  int opt;
  while ((opt = getopt(argc, argv, "d:ho:k:K:")) != -1)
  {
    switch(opt)
    {
      case 'h': help(); return 1;
      case 'd': note_data_block(data_blocks, optarg); break;
      case 'o': outfile = optarg; break;
      case 'k': keyfile = optarg; break;
      case 'K': keyid = optarg; break;
      default:
        fprintf(stderr, "Error: Unknown opt '%c'\n", opt);
        return 1;
    }
  }

  if (!outfile)
    error("missing -o");
  if (!keyfile)
    error("missing -k");
  if (!keyid)
    error("missing -K");

  EVP_PKEY *key = fwb_load_key(keyfile, PRIVATE_KEY);
  if (!key)
    error("unable to load private key");

  struct hash_context *hc = fwb_hash_context_new();
  if (!hc)
    error("failed to create hash context");

  FILE *fp = fopen(outfile, "wb");
  hwrite(hc, "FWB1", 4, fp); // format marker

  char key_id_buf[16];
  strncpy(key_id_buf, keyid, sizeof(key_id_buf));
  hwrite(hc, key_id_buf, sizeof(key_id_buf), fp); // key id

  // Random nonce, which we sign to prove that the following data is
  // *probably* good.
  uint8_t nonce[32];
  FILE *rnd = fopen("/dev/random", "r");
  if (fread(nonce, 32, 1, rnd) != 1)
    error("failed to source nonce bytes");
  hwrite(hc, nonce, sizeof(nonce), fp); // nonce

  struct signature ns = fwb_sign(nonce, sizeof(nonce), key);
  if (ns.len == 0)
    error("failed to sign nonce");
  uint16_t nslen = ns.len; // TODO ensure LE format
  hwrite(hc, &nslen, sizeof(nslen), fp); // nonce signature len
  hwrite(hc, ns.bytes, ns.len, fp); // nonce signature

  uint16_t parts = data_blocks.size();
  // TODO: ensure little-endian format
  hwrite(hc, &parts, sizeof(parts), fp); // num parts

  for (auto it : data_blocks)
    append_data_block(it.first, it.second, hc, fp); // data block parts

  struct hash_block hb, hbs;
  if (!fwb_hash_final(hc, &hb))
    error("failed to finalise hash");
  hwrite(hc, hb.md5, sizeof(hb.md5), fp); /// md5
  // store copy of our md5 for signing
  memcpy(hbs.md5, hb.md5, sizeof(hbs.md5));

  if (!fwb_hash_final(hc, &hb))
    error("failed to finalise hash");
  // switch to fwrite, done with hashing
  fwrite(hb.sha256, sizeof(hb.sha256), 1, fp); // sha256
  // store copy of our sha256 for signing
  memcpy(hbs.sha256, hb.sha256, sizeof(hbs.sha256));

  struct signature sig = fwb_sign(&hbs, sizeof(hbs), key);
  if (sig.len == 0)
    error("failed to sign");
  uint16_t siglen = sig.len;
  fwrite(&siglen, sizeof(siglen), 1, fp); // signature len
  fwrite(sig.bytes, sig.len, 1, fp); // signature

  fwrite("FWBZ", 4, 1, fp); // format trailer
  fclose(fp);

  fwb_hash_context_free(hc);

  return 0;
}
