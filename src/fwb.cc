#include "fwbcrypto.h"
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <fstream>
#include <regex>
#include <vector>

#define FWB_DIR "/etc/fwb"
#define KEY_SUBDIR "keys"

#define feedback(...) fprintf(stderr, __VA_ARGS__)

enum action_t { NONE, LIST, SHOWCFG, VERIFY, INSTALL };

struct header {
  char mark[3];
  char ver;
  char keyid[16];
  uint8_t nonce[32];
  uint16_t nonce_siglen;
};

struct part_header
{
  char name[16];
  uint64_t len;
};

typedef std::map<std::string, std::string> slot_map_t;

struct slot_cfg_t {
  std::vector<std::string> names;
  slot_map_t parts[2];
};


static void error(const char *msg)
{
  fprintf(stderr, "Error: %s\n", msg);
  exit(1);
}


static size_t hread(struct hash_context *hc, void *buf, size_t n, FILE *fp)
{
  size_t ret = fread(buf, n, 1, fp);
  if (!fwb_hash_update((const uint8_t *)buf, n, hc))
    error("hash update failed");
  return ret;
}


static void load_part(struct hash_context *hc, FILE *fp, action_t mode, const slot_map_t *parts)
{
  struct part_header ph;
  if (hread(hc, &ph, sizeof(ph), fp) != 1)
    error("part header read error");
  // TODO ensure LE format

  if (mode == LIST)
    printf("part %s:\t%" PRIu64 " bytes\n", ph.name, ph.len);

  int fd = -1;
  if (mode == INSTALL)
  {
    auto it = parts->find(ph.name);
    if (it == parts->end())
      feedback("Warning: skipping unknown part '%s'\n", ph.name);
    else
    {
      fd = open(it->second.c_str(), O_WRONLY | O_LARGEFILE);
      if (fd == -1)
      {
        fprintf(stderr, "Error: failed to open partition '%s': %s\n",
          it->second.c_str(), strerror(errno));
        exit(1);
      }
      else
        feedback("Installing '%s' to '%s'...\n", ph.name, it->second.c_str());
    }
  }

  char block[512];
  uint64_t left = ph.len;
  while (left)
  {
    unsigned n = left > sizeof(block) ? sizeof(block) : left;
    if (hread(hc, block, n, fp) != 1)
      error("data part read error");

    if (mode == INSTALL)
    {
      unsigned written = 0;
      do {
        ssize_t wrote = write(fd, block + written, n - written);
        if (wrote > 0)
          written += wrote;
        else if (wrote == 0)
          error("data part zero write?!");
        else
        {
          if (errno != EINTR && errno != EAGAIN)
          {
            fprintf(stderr, "Error: write failed: %s\n", strerror(errno));
            exit(1);
          }
        }
      } while (written != n);
    }

    left -= n;
  }

  if (fd >= 0)
    close(fd);
}


static EVP_PKEY *load_key_by_id(const std::string &dir, const char *keyid)
{
  std::string path{ dir + "/" + keyid };
  return fwb_load_key(path.c_str(), PUBLIC_KEY);
}


static slot_cfg_t load_slot_cfg(const std::string &dir)
{
  slot_cfg_t cfg;

  std::string fname{ dir + "/slots.cfg" };
  std::ifstream in{ fname };
  if (!in)
    error("unable to open slots.cfg");

  const std::regex re{
    "([-_/\\.:a-zA-Z0-9]{1,16})= *([-_/\\.:a-zA-Z0-9]+) +([-_/\\.:a-zA-Z0-9]+) *" };
  while (!in.eof())
  {
    std::string line;
    std::getline(in, line);
    std::smatch sm;
    if (std::regex_match(line, sm, re))
    {
      const std::string name = sm[1];
      const std::string part_a = sm[2];
      const std::string part_b = sm[3];
      cfg.names.push_back(name);
      cfg.parts[0][name] = part_a;
      cfg.parts[1][name] = part_b;
    }
    else if (line.size() && line[0] != '#')
      feedback("Warning: ignoring malformed slots.cfg line: %s\n", line.c_str());
  }

  return cfg;
}


static void err_mounted(const char *dev)
{
  fprintf(stderr, "Error: partition '%s' appears to be in use\n", dev);
  exit(1);
}


static void check_no_mounted(const slot_map_t &slots)
{
  // This isn't fool-proof. We should add things like looking at dm entries
  // too for better safety.

  // Check the list of mounts
  std::ifstream mounts("/proc/self/mounts");
  if (!mounts)
    error("unable to open /proc/self/mounts");
  while(mounts)
  {
    std::string line;
    std::getline(mounts, line);
    for (auto &e : slots)
    {
      if (line.find(e.second) == 0)
        err_mounted(e.second.c_str());
    }
  }

  // Check the root=/dev/xyz from the kernel command line
  std::ifstream cmdline("/proc/cmdline");
  if (!cmdline)
    error("unable to open /proc/cmdline");
  while(cmdline)
  {
    std::string line;
    std::getline(cmdline, line);
    std::regex re(".*root=([^ ]+).*");
    std::smatch sm;
    if (std::regex_match(line, sm, re))
    {
      const auto &dev = sm[1];
      for (auto &e : slots)
        if (e.second == dev)
          err_mounted(e.second.c_str());
    }
  }
}


void help()
{
  fprintf(stderr,
  "fwb -h\n"
  "  Print this help\n"
  "fwb -c [-C <configdir>] [-s <A|B>] [-n <name> -s <A|B>]\n"
  "  Print slot configuration, or look up specific slot device\n"
  "fwb -l -f <file> [-C <configdir>]\n"
  "  List contents of firmware bundle\n"
  "fwb -v -f <file> [-C <configdir>]\n"
  "  Verify firmware bundle without installing it\n"
  "fwb -i -s <A|B> -f <file> [-C <configdir>]\n"
  "  Install firmware bundle to specified slot set\n"
  "\n"
  "Examples:\n"
  "  Print slot configuration for both A and B slot sets:\n"
  "    fwb -c\n"
  "\n"
  "  Print slot configuration for only B slot set:\n"
  "    fwb -c -s B\n"
  "\n"
  "  Look up device for name 'kernel' in slot set A:\n"
  "    fwb -c -n kernel -s A\n"
  "\n"
  "  List contents of firmware bundle:\n"
  "    fwb -l -f /tmp/firmware.fwb\n"
  "\n"
  "  List contents of firmware bundle streamed on stdin:\n"
  "    cat /tmp/firmware.fwb | fwb -l -f -\n"
  "\n"
  "  Verify firmware bundle:\n"
  "    fwb -v -f /tmp/firmware.fwb && echo Ok || echo Broken\n"
  "\n"
  "  Install firmware bundle to slot set A:\n"
  "    fwb -i -s A -f /tmp/firmware.fwb\n"
  "\n"
  );
}


int main(int argc, char *argv[])
{
  FILE *fp = nullptr;
  action_t mode = NONE;
  std::string fwbdir{ FWB_DIR };
  int slot = -1;
  const char *partname = nullptr;

  int opt;
  while ((opt = getopt(argc, argv, "cC:f:hiln:vs:")) != -1)
  {
    switch(opt)
    {
      case 'c': mode = SHOWCFG; break;
      case 'C': fwbdir = optarg; break;
      case 'f':
        if (strlen(optarg) == 1 && *optarg == '-')
          fp = stdin;
        else
          fp = fopen(optarg, "rb");
        break;
      case 'h': help(); return 1;
      case 'i': mode = INSTALL; break;
      case 'l': mode = LIST; break;
      case 'n': partname = optarg; break;
      case 'v': mode = VERIFY; break;
      case 's':
        if (*optarg == 'A' || *optarg == 'a')
          slot = 0;
        else if (*optarg == 'B' || *optarg == 'b')
          slot = 1;
        else
        {
          fprintf(stderr, "Error: Unknown slot set '%s'\n", optarg);
          return 1;
        }
        break;
      default:
        fprintf(stderr, "Error: Unknown opt '%c'\n", opt);
        return 1;
    }
  }

  if (mode == NONE)
    error("no action specified");
  else if (mode == INSTALL && slot == -1)
    error("no slot set specified to install to");

  slot_cfg_t slots;
  if (mode == SHOWCFG || mode == INSTALL)
    slots = load_slot_cfg(fwbdir);

  if (mode == INSTALL)
    check_no_mounted(slots.parts[slot]);

  if (mode == SHOWCFG)
  {
    if (partname && slot != -1)
    {
      auto &partdev = slots.parts[slot][partname];
      if (partdev.size())
      {
        printf("%s\n", partdev.c_str());
        return 0;
      }
      fprintf(stderr, "Error: part '%s' not found in slots.cfg\n", partname);
      return 1;
    }
    else
    {
      for (auto &name : slots.names)
      {
        if (slot == -1)
          printf("%-16s %-30s %-30s\n",
            name.c_str(),
            slots.parts[0][name].c_str(),
            slots.parts[1][name].c_str());
        else
          printf("%-16s %-30s\n",
            name.c_str(),
            slots.parts[slot][name].c_str());
      }
    }
    return 0;
  }

  if (!fp)
    error("input file not available");

  struct hash_context *hc = fwb_hash_context_new();
  if (!hc)
    error("unable to create hash context");

  struct header hdr;
  if (hread(hc, &hdr, sizeof(hdr), fp) != 1)
    error("header read error");
  // TODO: ensure LE format

  if (strncmp("FWB", hdr.mark, 3) != 0)
    error("invalid file type");
  if (hdr.ver != '1')
    error("unsupported file version");

  char keyid[17] = { 0, };
  strncpy(keyid, hdr.keyid, 16);
  if (mode == LIST)
    printf("key id: %s\n", keyid);
  std::string keydir = fwbdir + "/" KEY_SUBDIR;
  EVP_PKEY *key = load_key_by_id(keydir, keyid);
  if (!key)
  {
    feedback("Error: key id '%s' not available\n", keyid);
    if (mode != LIST)
      return 1; // verify or install, both will fail, no point carrying on
  }

  uint8_t *ns = (uint8_t *)malloc(hdr.nonce_siglen);
  if (!ns)
    error("out of mem allocating sig buffer");

  if (hread(hc, ns, hdr.nonce_siglen, fp) != 1)
    error("failed to read nonce signature");

  struct signature nonce_sig = {
    .bytes = ns,
    .len = hdr.nonce_siglen,
  };
  if (!fwb_verify(&hdr.nonce, sizeof(hdr.nonce), key, nonce_sig))
    error("nonce signature not valid");

  free(ns);

  uint16_t num_parts;
  if (hread(hc, &num_parts, sizeof(num_parts), fp) != 1)
    error("failed to read num parts");
  // TODO ensure LE format

  for (unsigned i = 0; i < num_parts; ++i)
  {
    load_part(hc, fp, mode, slot != -1 ? &slots.parts[slot] : nullptr);
  }

  struct hash_block hb, hbin;
  if (!fwb_hash_final(hc, &hb))
    error("failed to finalise hash");

  if (hread(hc, hbin.md5, sizeof(hbin.md5), fp) != 1)
    error("read error md5 hash");

  if (memcmp(hbin.md5, hb.md5, sizeof(hb.md5)) != 0)
    error("md5 checksum mismatch");

  if (fread(hbin.sha256, sizeof(hbin.sha256), 1, fp) != 1)
    error("read error sha256 hash");

  if (!fwb_hash_final(hc, &hb))
    error("failed to finalise hash");

  if (memcmp(hbin.sha256, hb.sha256, sizeof(hb.sha256)) != 0)
    error("sha256 checksum mismatch");

  uint16_t siglen;
  if (fread(&siglen, sizeof(siglen), 1, fp) != 1)
    error("read error on sig len");

  if (siglen == 0)
    error("invalid sig len");

  uint8_t *sig = (uint8_t *)malloc(siglen);
  if (!sig)
    error("out of mem allocating sig buffer");

  if (fread(sig, siglen, 1, fp) != 1)
    error("failed to read signature");

  struct signature signature = {
    .bytes = sig,
    .len = siglen,
  };
  if (!fwb_verify(&hbin, sizeof(hbin), key, signature))
    error("signature not valid");
  if (mode == LIST)
    printf("signature: OK\n");

  char trailer[4];
  if (fread(trailer, sizeof(trailer), 1, fp) != 1)
    error("trailer read error");

  if (strncmp("FWBZ", trailer, 4) != 0)
    error("invalid trailer");

  if (mode == INSTALL)
    feedback("Install complete.\n");

  return 0;
}
