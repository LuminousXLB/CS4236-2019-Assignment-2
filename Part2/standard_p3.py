from binascii import hexlify
from os import urandom

from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad

from p3_e0446373 import PaddingOracleAttack

key = urandom(DES.key_size)


class PaddingOracle:

    # def __init__(self, host: str, port: int):
        # self.server = (host, port)

    def __call__(self, block0: bytes, block1: bytes) -> bytes:
        assert len(block0) == DES.block_size
        # assert len(block1) == DES.block_size

        cipher = DES.new(key, DES.MODE_CBC, block0)
        decrypt = cipher.decrypt(block1)
        result = all(map(lambda x: decrypt[-1] == x, decrypt[-decrypt[-1]:]))

        print(hexlify(decrypt), result)
        return result


if __name__ == "__main__":
    for l in range(1, 256):
        attack = PaddingOracleAttack(DES.block_size, PaddingOracle())

        message = urandom(l)
        padded = pad(message, DES.block_size)

        print(hexlify(padded))

        cipher = DES.new(key, DES.MODE_CBC, urandom(DES.key_size))
        ciphertext = cipher.encrypt(padded)
        ciphertext = cipher.iv + ciphertext

        blocks = [ciphertext[base:base+DES.block_size]
                  for base in range(0, len(ciphertext), DES.block_size)]

        block_pairs = list(zip(blocks, blocks[1:]))
        plaintext = b''
        
        for idx, (blk0, blk1) in enumerate(block_pairs):
            plaintext += attack(blk0, blk1, idx != len(block_pairs)-1)

        if plaintext == padded:
            print('[PASS] message length: ', l)
        else:
            print('[FAIL] message length: ', l)
            print(hexlify(padded))
            print(hexlify(plaintext))
