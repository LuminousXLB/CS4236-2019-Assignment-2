from binascii import hexlify
from os import urandom

from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad

from p4_e0446373 import EncryptionOracle

key = urandom(DES.key_size)


class DecryptionOracle:

    # def __init__(self, host: str, port: int):
        # self.server = (host, port)

    def __call__(self, block0: bytes, block1: bytes) -> bytes:
        assert len(block0) == DES.block_size
        # assert len(block1) == DES.block_size

        cipher = DES.new(key, DES.MODE_CBC, block0)

        return cipher.decrypt(block1)


if __name__ == "__main__":
    for l in range(256):
        message = urandom(l)

        encora = EncryptionOracle(DES.block_size, DecryptionOracle())
        cip = encora(message)
        cipher = DES.new(key, DES.MODE_CBC, cip[0])
        cip2 = cipher.encrypt(pad(message, DES.block_size))

        if b''.join(cip[1:]) == cip2:
            print('[PASS] message length: ', l)
        else:
            print('[FAIL] message length: ', l)
            print([hexlify(x) for x in cip])
            print([hexlify(x) for x in [cip[0]] + [cip2[base:base+DES.block_size]
                                                   for base in range(0, len(cip2), DES.block_size)]])
            exit(-1)
