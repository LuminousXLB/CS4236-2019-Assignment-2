import socket
import sys
from os import urandom

BLOCK_SIZE = 128 // 8 // 2


class DecryptionOracle:
    server = ("localhost", 5000)
    template = "dec_oracle,0x{:016x},0x{:016x}\n"

    def __init__(self, host: str, port: int):
        self.server = (host, port)

    def __call__(self, block0: bytes, block1: bytes) -> bytes:
        assert len(block0) == BLOCK_SIZE
        assert len(block1) == BLOCK_SIZE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.server)

        sock.sendall(self.build_message(block0, block1))

        r = sock.recv(18).decode('ascii')

        return int(r, 16).to_bytes(BLOCK_SIZE, 'big')

    def build_message(self, block0: bytes, block1: bytes) -> bytes:
        return self.template.format(*map(
            lambda b: int.from_bytes(b, 'big'),
            [block0, block1]
        )).encode('ascii')


def xor(a, b):
    assert len(a) == len(b)
    return bytes([x ^ y for (x, y) in zip(a, b)])


class EncryptionOracle:
    block_size = 128 // 2 // 8

    def __init__(self, block_size: int, decryption_oracle: DecryptionOracle):
        self.blk_size = block_size
        self.oracle = decryption_oracle

    def __call__(self, message: bytes) -> bytes:
        # partition and pad the message into separate blocks
        plaintext = self.partition_and_pad(message)

        # randomly generate the last cipher block
        # this random values act as an IV
        ciphertext = [urandom(self.blk_size)]

        # a zero block
        zero = bytes(self.blk_size)

        # start at the last one
        for idx in reversed(range(len(plaintext))):
            # resp := Dec_k( zero || C_{idx} ) = zero ^ F^{-1}_k( C_{idx} )
            # resp ^ zero = F^{-1}_k( C_{idx} ) = C_{idx-1} ^ P_{idx}
            # C_{idx-1} = resp ^ zero ^ P_{idx} = resp ^ P_{idx}

            # query the decryption of [zero || C_{idx}], i.e. F^{-1}_k( C_{idx-1} )
            resp = self.oracle(zero, ciphertext[0])
            # insert the previous cipher block
            ciphertext.insert(0, xor(plaintext[idx], resp))

        return ciphertext

    @staticmethod
    def partition_and_pad(plaintext: bytes) -> [bytes]:
        # padding
        pad_len = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
        if pad_len == 0:
            pad_len = BLOCK_SIZE

        assert 0 < pad_len <= BLOCK_SIZE
        padded = plaintext + bytes([pad_len]*pad_len)

        # partition
        return [padded[base:base+BLOCK_SIZE] for base in range(0, len(padded), BLOCK_SIZE)]


if __name__ == "__main__":
    # verify the command line parameters
    if len(sys.argv) != 2:
        print("Error: Run with wrong number of args", file=sys.stderr)
        print("Usage: python3 %s <message>" % sys.argv[0], file=sys.stderr)
        print(sys.argv)
        exit(-1)

    # read the server address
    HOST = "localhost"
    PORT = 5000

    f = open("oracle/port", "r")
    lines = f.readlines()
    PORT = int(lines[0].strip())

    # initialize an decryption oracle and an encryption oracle instance
    oracle = DecryptionOracle(HOST, PORT)
    encrypt = EncryptionOracle(BLOCK_SIZE, oracle)

    ciphertext_blocks = encrypt(sys.argv[1].encode('ascii'))

    # format and print the ciphertext
    print(' '.join([
        "0x{:016x}".format(int.from_bytes(b, 'big')) for b in ciphertext_blocks
    ]))
