#!/usr/bin/python3
from binascii import hexlify, unhexlify
import subprocess


BLOCK_LENGTH = 16


# This is a port to the openssl CLI
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes):
    return subprocess.run(
        [
            'openssl',
            'enc', '-aes-128-cbc',
            '-K', hexlify(key).decode('ascii'),
            '-iv', hexlify(iv).decode('ascii')
        ],
        input=plaintext,
        capture_output=True
    ).stdout


def xor(bytes1: bytes, bytes2: bytes):
    return bytes([b1 ^ b2 for (b1, b2) in zip(bytes1, bytes2)])


def pad_block(message: bytes):
    padding_length = BLOCK_LENGTH - (len(message) % BLOCK_LENGTH)
    padded = message + bytes(padding_length * [padding_length])
    assert len(padded) % BLOCK_LENGTH == 0

    return padded


if __name__ == "__main__":
    KEY = unhexlify('00112233445566778899aabbccddeeff')  # Known only to Bob
    CIP = unhexlify('bef65565572ccee2a9f9553154ed9498')  # Known to both
    IV1 = unhexlify('31323334353637383930313233343536')  # Known to both
    IV2 = unhexlify('31323334353637383930313233343537')  # Known to both

    # Challenge Yes
    yes_challenge = xor(xor(IV1, IV2), pad_block(b'Yes'))
    yes_response = cbc_encrypt(yes_challenge, KEY, IV2)

    if yes_response[:BLOCK_LENGTH] == CIP:
        print("Bob said Yes")
    else:
        print("Bob said No")

    # Challenge No
    no_challenge = xor(xor(IV1, IV2), pad_block(b'No'))
    no_response = cbc_encrypt(no_challenge, KEY, IV2)

    if no_response[:BLOCK_LENGTH] == CIP:
        print("Bob said No")
    else:
        print("Bob said Yes")
