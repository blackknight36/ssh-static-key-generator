#!/usr/bin/env python2.7
import commands, codecs, ecdsa, struct, sys, textwrap

from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
from Crypto import Random

import nacl.signing as ed25519
from nacl.encoding import Base64Encoder
from nacl.encoding import HexEncoder

# This function returns an integer value as a binary value
def to_bytes(i):
    return struct.pack('>I', i)

class PRNG(object):
  def __init__(self, seed):
    self.index = 0
    self.seed = seed
    self.buffer = b""

  def __call__(self, n):
    while len(self.buffer) < n:
        self.buffer += HMAC.new(self.seed + struct.pack("<I", self.index)).digest()
        self.index += 1
    result, self.buffer = self.buffer[:n], self.buffer[n:]
    return result

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

def encode_ed25519_pub_key(keytype, comment):
    pubkey = to_bytes(len(keytype))
    pubkey += keytype
    pubkey += to_bytes(len(keydata[keytype].verify_key.encode()))
    pubkey += keydata[keytype].verify_key.encode()
    return codecs.encode(pubkey, 'base64').rstrip()

armor_start = "-----BEGIN OPENSSH PRIVATE KEY-----"
armor_end = "-----END OPENSSH PRIVATE KEY-----"
comment = ''

# The seed file is 32 bytes of random data taken from /dev/urandom
# dd if=/dev/urandom of=my-secret-seed bs=1 count=32
seed = open("/home/00/d861703/Nextcloud/projects/scripts/my-secret-seed", "rb").read()

keydata = {}

keydata['ssh-rsa'] = RSA.generate(4096, randfunc=PRNG(seed))

keydata['ecdsa-sha2-nistp521'] = ecdsa.SigningKey.generate(entropy=PRNG(seed), curve=ecdsa.NIST521p)
# Convert ecdsa key to format used by OpenSSH
ecdsa_pub = commands.getoutput("echo '%s' | ssh-keygen -i -m PKCS8 -f /dev/stdin" %keydata['ecdsa-sha2-nistp521'].get_verifying_key().to_pem())

keydata['ssh-ed25519'] = ed25519.SigningKey(seed)
ed25519_base64 = codecs.encode(putEd25519Key(keydata['ssh-ed25519'], comment), 'base64').rstrip()

# Write key data to disk
f = open('ssh_host_rsa_key', 'wb+')
f.write(keydata['ssh-rsa'].exportKey('PEM'))
f.write("\n")
f.close()

f2 = open('ssh_host_rsa_key.pub', 'wb+')
f2.write(keydata['ssh-rsa'].publickey().exportKey('OpenSSH'))
f2.write("\n")
f2.close()

f3 = open('ssh_host_ecdsa_key', 'wb+')
f3.write(keydata['ecdsa-sha2-nistp521'].to_pem())
f3.close()

f4 = open('ssh_host_ecdsa_key.pub', 'wb+')
f4.write(ecdsa_pub + "\n")
f4.close()

f5 = open('ssh_host_ed25519_key', 'wb+')
f5.write(armor_start + "\n" + ed25519_base64 + "\n" + armor_end + "\n")
f5.close()

f6 = open('ssh_host_ed25519_key.pub', 'wb+')
f6.write("ssh-ed25519" + " " + encode_ed25519_pub_key('ssh-ed25519', comment) + " " + comment + "\n")
f6.close()
