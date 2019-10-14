from oracle_python import pad_oracle, dec_oracle
from pathlib import Path
import struct
from binascii import hexlify

CIPHERTEXT_DIR = Path('../../ciphertext')
BLOCK_SIZE = 128 // 2 // 8


def decode(blocks: [str]):
    return [list(struct.pack('>Q', int(s, 16))) for s in blocks]


def encode(blocks: [[int]]):
    return ['0x'+hexlify(bytes(b)).decode('ascii') for b in blocks]


def query(blocks):
    params = encode(blocks)
    assert len(params) == 2
    return pad_oracle(*params).decode('ascii') == '1'


def find_padding_length(cip_blocks):
    assert len(cip_blocks) > 1

    dup = [list(block) for block in cip_blocks]

    for idx in range(BLOCK_SIZE):
        dup[-2][idx] = (cip_blocks[-2][idx] ^ 0x01) % 0xff
        ret = query([bytes(block) for block in dup])

        if not ret:
            return BLOCK_SIZE - idx


def fix_padding(cip_blocks, padding_length):
    assert len(cip_blocks) > 1

    dup = [list(block) for block in cip_blocks]

    for i in range(256):
        dup[-2][-padding_length] = i
        ret = query([bytes(block) for block in dup])
        if ret:
            return i


def pad_oracle_attack(cip_blocks):
    assert len(cip_blocks) == 2

    pad_len = find_padding_length(cip_blocks)
    plaintext = [0] * (BLOCK_SIZE-pad_len) + [pad_len]*pad_len

    while pad_len < BLOCK_SIZE:
        # modify padding
        new_iv = [p ^ c for (p, c) in zip(plaintext, cip_blocks[-2])]

        pad_len += 1
        for idx in range(-pad_len, 0):
            new_iv[idx] ^= pad_len

        # fix padding
        c_fixed = fix_padding([new_iv, cip_blocks[-1]], pad_len)

        # reveal plaintext byte
        p_revealed = c_fixed ^ pad_len ^ cip_blocks[-2][-pad_len]
        plaintext[-pad_len] = p_revealed

    return plaintext


def normalize_plaintext(plaintext):
    pt = plaintext[:-plaintext[-1]]
    return bytes(pt)


if __name__ == "__main__":
    for file_path in CIPHERTEXT_DIR.iterdir():
        content = file_path.read_text()
        print(content.split('\t'))
        plaintext = pad_oracle_attack(decode(content.split('\t')))
        print('\t', normalize_plaintext(plaintext))

    # content = '0x4400a04574707149\t0x15b8cf27546da944'
    # print(content.split('\t'))
    # plaintext = pad_oracle_attack(decode(content.split('\t')))
    # print('\t', normalize_plaintext(plaintext))
