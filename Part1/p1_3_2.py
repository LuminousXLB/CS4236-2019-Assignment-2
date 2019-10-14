#!/usr/bin/python3
from binascii import hexlify, unhexlify


def xor(bytes1: bytes, bytes2: bytes):
    """ bitwise XOR bytes1 with bytes2 """
    return bytes([b1 ^ b2 for (b1, b2) in zip(bytes1, bytes2)])


if __name__ == "__main__":
    # Known Information
    P1 = b'This is a known message!'
    C1 = unhexlify(b'a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159')
    C2 = unhexlify(b'bf73bcd3509299d566c35b5d450337e1bb175f903fafc159')

    # Calculate P2
    P2 = xor(xor(P1, C1), C2)
    print(P2.decode('ascii'))
