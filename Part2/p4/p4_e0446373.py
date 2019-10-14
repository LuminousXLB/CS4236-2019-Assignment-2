from oracle_python import pad_oracle, dec_oracle
from pathlib import Path
import struct
from binascii import hexlify
from os import urandom

CIPHERTEXT_DIR = Path('../../ciphertext')
BLOCK_SIZE = 128 // 2 // 8


def decode(blocks: [str]):
    return [list(struct.pack('>Q', int(s, 16))) for s in blocks]


def encode(blocks: [[int]]):
    return ['0x'+hexlify(bytes(b)).decode('ascii') for b in blocks]


def query(blocks):
    params = encode(blocks)
    assert len(params) == 2
    return decode([dec_oracle(*params).decode('ascii')])[0]


def padding_and_split(plaintext: bytes):
    pad_len = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE

    assert pad_len > 0
    assert pad_len <= BLOCK_SIZE

    padded = plaintext + bytes([pad_len]*pad_len)

    assert len(padded) % BLOCK_SIZE == 0

    return [padded[base:base+BLOCK_SIZE] for base in range(0, len(padded), BLOCK_SIZE)]


def xor(a, b):
    assert len(a) == len(b)
    return [x ^ y for (x, y) in zip(a, b)]


def enc_oracle(message: str):
    plaintext = padding_and_split(message)
    print(plaintext)

    ciphertext = [list(urandom(BLOCK_SIZE)) for _ in range(len(plaintext) + 1)]

    for idx in range(len(plaintext), 0, -1):
        resp = query(ciphertext[idx-1:idx+1])
        ciphertext[idx] = xor(plaintext[idx-1], xor(resp, ciphertext[idx-1]))

    return ciphertext


if __name__ == "__main__":
    msg = "This is the message that needs to be encrypted."
    ciphertext = enc_oracle(msg.encode('ascii'))
    print(encode(ciphertext))
