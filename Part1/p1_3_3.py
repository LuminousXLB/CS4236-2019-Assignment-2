#!/usr/bin/python3
from binascii import hexlify, unhexlify
import subprocess


def aes_cbc_oracle(key):
    def cbc_encrypt(plaintext: bytes, iv: bytes):
        """ this is a port to the openssl CLI """
        p = subprocess.Popen(
            [
                'openssl',
                'enc', '-aes-128-cbc',
                '-K', hexlify(key).decode('ascii'),
                '-iv', hexlify(iv).decode('ascii')
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        out, _err = p.communicate(input=plaintext)

        return out

    return cbc_encrypt


def pad_block(block_size: int, message: bytes):
    """ pad the message using PKCS#7 """
    padding_length = block_size - (len(message) % block_size)
    padded = message + bytes(padding_length * [padding_length])

    assert len(padded) % block_size == 0
    assert len(padded) > len(message)

    return padded


def query(oracle: callable, message: bytes, IV1: bytes, IV2: bytes):
    """ knowing a IV2, ask the oracle to return the ciphertext for message using IV1 """
    print('INFO message  ', hexlify(message).decode('ascii'))

    query = bytes([m ^ i ^ v for (m, i, v) in zip(message, IV1, IV2)])
    print('INFO query    ', hexlify(query).decode('ascii'))

    response = oracle(query, IV2)
    print('INFO response ', hexlify(response).decode('ascii'))

    return response


if __name__ == "__main__":
    # Known Information
    KEY = unhexlify('00112233445566778899aabbccddeeff')  # Known only to Bob
    CIP = unhexlify('bef65565572ccee2a9f9553154ed9498')  # Known to both
    IV1 = unhexlify('31323334353637383930313233343536')  # Known to both
    IV2 = unhexlify('31323334353637383930313233343537')  # Known to both

    BLOCK_SIZE = 16

    oracle = aes_cbc_oracle(KEY)

    print(">>> Try `Yes`")
    padded_yes = pad_block(BLOCK_SIZE, b'Yes')
    yes_response = query(oracle, padded_yes, IV1, IV2)
    if yes_response[:BLOCK_SIZE] == CIP:
        print("Bob said Yes")
    else:
        print("Bob said No")

    print("")
    print(">>> Try `No`")
    padded_no = pad_block(BLOCK_SIZE, b'No')
    no_response = query(oracle, padded_no, IV1, IV2)

    if no_response[:BLOCK_SIZE] == CIP:
        print("Bob said No")
    else:
        print("Bob said Yes")
