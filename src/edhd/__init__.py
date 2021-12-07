import hashlib
import hmac
import re
from functools import reduce
from nacl import bindings

class Xprv:

  def __init__(self, private_key, prefix, chain_code):
    self.prefix = prefix
    self.private_key = private_key
    self.public_key = bindings.crypto_scalarmult_ed25519_base_noclamp(private_key)
    self.chain_code = chain_code

  def from_private_key_and_chain_code(private_key, prefix, chain_code):
    return Xprv(private_key, prefix, chain_code)

  def to_xpub(self):
    return Xpub.from_public_key_and_chain_code(self.public_key, self.chain_code)

  def derive_index(self, index):
    zmac = hmac.new(self.chain_code, digestmod='sha512')
    imac = hmac.new(self.chain_code, digestmod='sha512')
    seri = index.to_bytes(4, 'little')
    if index & 0x80000000 == 0:
      # Normal derivation:
      # Z = HMAC-SHA512(Key = cpar, Data = 0x02 || serP(point(kpar)) || ser32(i)).
      # I = HMAC-SHA512(Key = cpar, Data = 0x03 || serP(point(kpar)) || ser32(i)).
      zmac.update(b'\x02')
      zmac.update(self.public_key)
      zmac.update(seri)
      imac.update(b'\x03')
      imac.update(self.public_key)
      imac.update(seri)
    else:
      # Hardened derivation:
      # Z = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(left(kpar)) || ser32(i)).
      # I = HMAC-SHA512(Key = cpar, Data = 0x01 || ser256(left(kpar)) || ser32(i)).
      zmac.update(b'\x00')
      zmac.update(self.private_key)
      zmac.update(seri)
      imac.update(b'\x01')
      imac.update(self.private_key)
      imac.update(seri)

    zout = zmac.digest()
    zl = zout[0:32]
    zr = zout[32:]

    # left = kl + 8 * trunc28(zl)
    left = (int.from_bytes(self.private_key, 'little') \
            + 8 * int.from_bytes(zl[0:28], 'little')).to_bytes(32, 'little')
    # right = zr + kr
    right = (int.from_bytes(self.prefix, 'little') \
             + int.from_bytes(zr, 'little')).to_bytes(33, 'little')[0:32]

    iout = imac.digest()
    chain_code = iout[32:]

    return Xprv.from_private_key_and_chain_code(left, right, chain_code)

  def derive_path(self, path):
    if re.match(r'^m', path):
      path = path[1:]
    if not re.match(r'^/', path):
      raise ValueError
    path = path[1:]
    indices = map(lambda index: (0x80000000 | int(index[1:], 10)) if re.match(r'^\'', index) else int(index, 10), re.split('/', path))
    return reduce(lambda xprv, index: xprv.derive_index(index), indices, Xprv(self.private_key, self.prefix, self.chain_code))

  def sign(self, message):
    r = bindings.crypto_core_ed25519_scalar_reduce(
      hashlib.sha512(self.prefix + message).digest(),
    )
    R = bindings.crypto_scalarmult_ed25519_base_noclamp(r)
    hram = bindings.crypto_core_ed25519_scalar_reduce(
      hashlib.sha512(R + self.public_key + message).digest(),
    )
    S = bindings.crypto_core_ed25519_scalar_add(
      bindings.crypto_core_ed25519_scalar_mul(hram, self.private_key),
      r,
    )
    return R + S

  def verify(self, signature, message):
    return self.to_xpub().verify(signature, message)

class Xpub:

  def __init__(self, public_key, chain_code):
    self.public_key = public_key
    self.chain_code = chain_code

  def from_public_key_and_chain_code(public_key, chain_code):
    return Xpub(public_key, chain_code)

  def derive_index(self, index):
    zmac = hmac.new(self.chain_code, digestmod='sha512')
    imac = hmac.new(self.chain_code, digestmod='sha512')
    seri = index.to_bytes(4, 'little')
    if index & 0x80000000 == 0:
      zmac.update(b'\x02')
      zmac.update(self.public_key)
      zmac.update(seri)
      imac.update(b'\x03')
      imac.update(self.public_key)
      imac.update(seri)
    else:
      raise ValueError('Cannot derive hardened index with public key')

    zout = zmac.digest()
    zl = zout[0:32]

    # left = kl + 8 * trunc28(zl)
    left = bindings.crypto_core_ed25519_add(
      self.public_key,
      bindings.crypto_scalarmult_ed25519_base_noclamp(
        (8 * int.from_bytes(zl[0:28], 'little')).to_bytes(32, 'little')
      ),
    )

    iout = imac.digest()
    chain_code = iout[32:]

    return Xpub.from_public_key_and_chain_code(left, chain_code)

  def derive_path(self, path):
    if re.match(r'^m', path):
      path = path[1:]
    if not re.match(r'^/', path):
      raise ValueError
    path = path[1:]
    indices = map(lambda index: (0x80000000 | int(index[1:], 10)) if re.match(r'^\'', index) else int(index, 10), re.split('/', path))
    return reduce(lambda xprv, index: xprv.derive_index(index), indices, Xpub(self.public_key, self.chain_code))

  def verify(self, signature, message):
    return bindings.crypto_sign_open(signature + message, self.public_key)
