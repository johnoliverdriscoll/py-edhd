from nacl import bindings
import random, unittest
import src.edhd

class Edhd(unittest.TestCase):

  def test_xprv_to_xpub(self):
    u = random.SystemRandom().randrange(2 ** 256).to_bytes(32, 'little')
    u = [x for x in u]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = bindings.crypto_core_ed25519_scalar_reduce(bytes(u + [0] * 32))
    prefix = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    chain_code = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    xprv = src.edhd.Xprv(u, prefix, chain_code)
    xpub = xprv.to_xpub()
    pk = bindings.crypto_scalarmult_ed25519_base_noclamp(xprv.private_key)
    assert xpub.public_key == pk
    assert xpub.chain_code == xprv.chain_code

  def test_derive_index(self):
    u = random.SystemRandom().randrange(2 ** 256).to_bytes(32, 'little')
    u = [x for x in u]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = bindings.crypto_core_ed25519_scalar_reduce(bytes(u + [0] * 32))
    prefix = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    prefix = bindings.crypto_core_ed25519_scalar_reduce(prefix + b'\x00' * 32)
    chain_code = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    xprv = src.edhd.Xprv(u, prefix, chain_code)
    xpub = xprv.to_xpub()
    assert xprv.derive_index(0).public_key == xpub.derive_index(0).public_key
    message = b'hello world'
    sig = xprv.derive_index(0).sign(message)
    assert xpub.derive_index(0).verify(sig, message)

  def test_derive_path(self):
    u = random.SystemRandom().randrange(2 ** 256).to_bytes(32, 'little')
    u = [x for x in u]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = bindings.crypto_core_ed25519_scalar_reduce(bytes(u + [0] * 32))
    prefix = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    prefix = bindings.crypto_core_ed25519_scalar_reduce(prefix + b'\x00' * 32)
    chain_code = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    xprv = src.edhd.Xprv(u, prefix, chain_code)
    xprv1 = xprv.derive_path('m/499/1')
    xprv2 = xprv.derive_index(499).derive_index(1)
    assert xprv1.private_key == xprv2.private_key
    assert xprv1.prefix == xprv2.prefix
    assert xprv1.chain_code == xprv2.chain_code

  def test_sign_and_verify(self):
    u = random.SystemRandom().randrange(2 ** 256).to_bytes(32, 'little')
    u = [x for x in u]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = bindings.crypto_core_ed25519_scalar_reduce(bytes(u + [0] * 32))
    prefix = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    chain_code = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    xprv = src.edhd.Xprv(u, prefix, chain_code)
    message = b'hello world'
    assert xprv.verify(xprv.sign(message), message)

  def test_derive_sign_and_verify(self):
    u = random.SystemRandom().randrange(2 ** 256).to_bytes(32, 'little')
    u = [x for x in u]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = bindings.crypto_core_ed25519_scalar_reduce(bytes(u + [0] * 32))
    prefix = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    chain_code = random.SystemRandom().randrange(1, 2 ** 256).to_bytes(32, 'little')
    xprv = src.edhd.Xprv(u, prefix, chain_code)
    message = b'hello world'
    assert xprv.verify(xprv.sign(message), message)
    assert xprv.to_xpub().derive_path('m/1/2').verify(xprv.derive_path('m/1/2').sign(message), message)
