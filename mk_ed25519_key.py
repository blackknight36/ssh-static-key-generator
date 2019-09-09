#!/usr/bin/env python2.7

# see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
# for a description of the key file format

# This info is taken from https://coolaj86.com/articles/the-openssh-private-key-format/

# "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
# 32-bit length, "none"   # ciphername length and string
# 32-bit length, "none"   # kdfname length and string
# 32-bit length, nil      # kdf (0 length, no kdf)
# 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
# 32-bit length, sshpub   # public key in ssh format
#     32-bit length, keytype
#     32-bit length, pub0
#     32-bit length, pub1
# 32-bit length for rnd+prv+comment+pad
#     64-bit dummy checksum?  # a random 32-bit int, repeated
#     32-bit length, keytype  # the private key (including public)
#     32-bit length, pub0     # Public Key parts
#     32-bit length, pub1
#     32-bit length, prv0     # Private Key parts
#     ...                     # (number varies by type)
#     32-bit length, comment  # comment string
#     padding bytes 0x010203  # pad to blocksize (see notes below)

# https://www.devdungeon.com/content/working-binary-data-python
# Pass "wb" to write a new file, or "ab" to append
#with open("test.txt", "wb") as binary_file:
#    # Write text or bytes to the file
#    binary_file.write("Write text by encoding\n".encode('utf8'))
#    num_bytes_written = binary_file.write(b'\xDE\xAD\xBE\xEF')
#    print("Wrote %d bytes." % num_bytes_written)

import base64, codecs, struct, sys, textwrap
#from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from nacl.encoding import HexEncoder

def to_bytes(i):
    return struct.pack('>I', i)

def putPublicKey(pubkey):
  return "ssh-ed25519" + pubkey

def putPrivateKey(pubkey, privkey, comment):
  return "ssh-ed25519" + pubkey + privkey + comment

# This function is based on the file format described at https://coolaj86.com/articles/the-openssh-private-key-format
def putEd25519Key(key, comment):
  auth_magic = b"openssh-key-v1\x00"
  keytype = b'ssh-ed25519'
  privkey = key.encode()
  pubkey = key.verify_key.encode()

  s = auth_magic
  s += to_bytes(4)
  s += b'none'
  s += to_bytes(4)
  s += b'none'
  s += to_bytes(0)
  # number of keys - hardcoded to 1
  s += to_bytes(1)
  # total size of public key data = len(keytype) + len(pubkey) + 8 bytes of length data
  s += to_bytes(len(keytype) + len(pubkey) +8)
  s += to_bytes(len(keytype))
  s += keytype
  s += to_bytes(len(pubkey))
  s += pubkey

  privkey_block = to_bytes(0) + to_bytes(0) + to_bytes(len(keytype)) + keytype + to_bytes(len(pubkey)) + pubkey + to_bytes(len(privkey) + len(pubkey)) + privkey + pubkey + to_bytes(len(comment)) + comment
  # Add padding until list is a multiple of the cipher block size (8) - See the sshkey_private_to_blob2 function in sshkey.c
  n = 1

  while len(privkey_block) % 8 != 0:
      privkey_block += chr(n & 0xFF)
      n += 1

  s += to_bytes(len(privkey_block))
  s += privkey_block
  return s

armor_start = "-----BEGIN OPENSSH PRIVATE KEY-----"
armor_end = "-----END OPENSSH PRIVATE KEY-----"

# The seed file is 32 bytes of random data taken from /dev/urandom
# dd if=/dev/urandom of=my-secret-seed bs=1 count=32
seed = open("my-secret-seed", "rb").read()

sk = SigningKey(seed)
vk = sk.verify_key
c = b'root@localhost'

keydata =  putEd25519Key(sk, c)
keydata_64 = textwrap.wrap(codecs.encode(keydata, 'base64'), width=70)

#print(keydata)

data = armor_start + "\n" + "\n".join(keydata_64) + "\n" + armor_end

print(armor_start)
print("\n".join(keydata_64))
print(armor_end)

#print(data)

#f = open('key.txt', 'wb+')
#f.write(data)
#f.write("\n".join(keydata_64))
#f.write("\n")
#f.close()
