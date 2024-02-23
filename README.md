# FirmWare Bundle utilities

Small utilities to assist with implementing A/B upgrades on embedded Linux
devices.

Essentially allows bundling multiple partition images into a single bundle
file, and signing it all.

On the receiving end, the firmware bundle can be processed in a streaming
manner to avoid needing to first download the file, which may be impossible
depending on disk space availability.

There is no explicit support for [de]compression of data. The firmware bundle
may be separately compressed and decompressed on the fly while streaming the
output into `fwb`.

## Generating signing & verification key
`openssl ecparam -genkey -name prime256v1 -noout -out key1.pem`
`openssl ec -in key1.pem -pubout -out pubkey1.pem`

## fwb configuration

The `fwb` utility relies on configuration data typically stored under
`/etc/fwb`. A different directory may be specified with `-C <dir>` when
running `fwb`.

### Verification keys

All available verification keys should be copied into `/etc/fwb/keys/` with
a filename matching the `keyid` value supplied to `fwbcreate`.

For example, if the key was generated as shown above, the `pubkey1.pem` file
would typically be copied to `/etc/fwb/keys/key1`, and the keyid `key1` used
with `fwbcreate`.

### A/B slot configuration

For `fwb` to know where to extract the firmware bundle data to, the file
`/etc/fwb/slots.cfg` is used. The format is simple - the part name followed
by an equals sign, and then the two device names separated by space.
Blank lines and lines beginning with `#` are ignored and treated as comments.

Example:
```
# /dev/mmcblk0p1 is our /config - leave it alone!
kernel=/dev/mmcblk0p2 /dev/mmcblk0p3
root=/dev/mmcblk0p4 /dev/mmcblk0p5
```


## fwbcreate usage
```
fwbcreate -k <privatekey> -K <keyid> -o <outfile.fwb> -d <name:/path/to/source.img> [-d ...]
  Create firmware bundle and sign it.

Examples:
  Create bundle with boot & root parts, signed with 'key1':
    fwbcreate -k key1.key -K key1 -o upgrade.fwb -d boot:boot.img -d root:rootfs.ext2

```

## fwb usage

```
fwb -h
  Print this help
fwb -c [-C <configdir>] [-s <A|B>] [-n <name> -s <A|B>]
  Print slot configuration, or look up specific slot device
fwb -l -f <file> [-C <configdir>]
  List contents of firmware bundle
fwb -v -f <file> [-C <configdir>]
  Verify firmware bundle without installing it
fwb -i -s <A|B> -f <file> [-C <configdir>]
  Install firmware bundle to specified slot set

Examples:
  Print slot configuration for both A and B slot sets:
    fwb -c

  Print slot configuration for only B slot set:
    fwb -c -s B

  Look up device for name 'kernel' in slot set A:
    fwb -c -n kernel -s A

  List contents of firmware bundle:
    fwb -l -f /tmp/firmware.fwb

  List contents of firmware bundle streamed on stdin:
    cat /tmp/firmware.fwb | fwb -l -f -

  Verify firmware bundle:
    fwb -v -f /tmp/firmware.fwb && echo Ok || echo Broken

  Install firmware bundle to slot set A:
    fwb -i -s A -f /tmp/firmware.fwb
```

## File format
`FWB1` - four bytes, file marker, version 1
`keyid` - 16 bytes, zero filled
`nonce` - 32 bytes
`nonce_siglen` - uint16\_t length of following signature
`nonce_signature` - signature over `nonce` bytes, signed by key identified by `keyid` (this allows an early check whether the following data is likely to be valid or not)
`num_parts` - uint16\_t number of data parts following
```
struct {
  char name[16];
  uint64_t len_le;
  uint8_t bytes[];
} part;
```
data part block, repeated `num_parts` times. `len_le` indicates number of data
bytes that follows within the block.
`md5hash` - 16 bytes, md5 from start of FWB1 to end of parts
`sha256hash` - 32 bytes, sha256 from start of FWB to end of md5hash (intentionally overlapped to make collision attacks harder)
`signature_len` - uint16\_t length of the following signature
`signature` - signature of md5hash||sha256hash
`FWBZ` - file trailer mark

All uintN\_t types are in little-endian order.
