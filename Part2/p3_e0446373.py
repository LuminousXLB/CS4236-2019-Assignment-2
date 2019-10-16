import socket
import sys

BLOCK_SIZE = 128 // 2 // 8


class PaddingOracle:
    server = ("localhost", 5000)
    template = "pad_oracle,0x{:016x},0x{:016x}\n"

    def __init__(self, host: str, port: int):
        self.server = (host, port)

    def __call__(self, block0: bytes, block1: bytes) -> bool:
        assert len(block0) == BLOCK_SIZE
        assert len(block1) == BLOCK_SIZE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.server)

        sock.sendall(self.build_message(block0, block1))

        return sock.recv(1) == b'1'

    def build_message(self, block0: bytes, block1: bytes) -> bytes:
        return self.template.format(*map(
            lambda b: int.from_bytes(b, 'big'),
            [block0, block1]
        )).encode('ascii')


class PaddingOracleAttack:
    block_size = 128 // 2 // 8

    def __init__(self, block_size: int, padding_oracle: PaddingOracle):
        self.blk_size = block_size
        self.oracle = padding_oracle

    def __call__(self, init_vector: bytes, cipher_block: bytes) -> bytes:
        assert len(init_vector) == self.blk_size
        assert len(cipher_block) == self.blk_size

        self.c0 = bytearray(init_vector)
        self.c1 = bytearray(cipher_block)

        # find the padding length
        pad_len = self.probe_padding_length()

        # save the confirmed plain_text bytes
        self.p_text = bytearray([pad_len]*pad_len)

        while len(self.p_text) < self.blk_size:
            # generate a new IV to increase the padding length
            new_iv = self.construct_proceeding_iv()
            assert len(new_iv) == self.blk_size

            # tune the byte to fix the padding and reveal a byte
            revealed_byte = self.fix_padding(new_iv)
            assert 0 <= revealed_byte <= 0xff

            # update the plaintext, prepend the revealed byte to the plaintext
            self.p_text.insert(0, revealed_byte)

        # remove the padding and return the plaintext
        return bytes(self.p_text[:-self.p_text[-1]])

    def probe_padding_length(self) -> int:
        c0 = self.c0.copy()

        # modify a byte one by on from the first one
        for idx in range(self.blk_size):
            c0[idx] ^= 0x01

            # stop until the oracle returns `Invalid Padding`
            # the byte modified finally is the first byte of the padding
            if not self.oracle(c0, self.c1):
                return self.blk_size - idx

        return 0

    def construct_proceeding_iv(self) -> bytearray:
        assert len(self.p_text) < self.blk_size

        # to reaveal the next unknown byte
        # set the padding lenth to `1 + # of known bytes`
        pad_len = len(self.p_text) + 1
        # and generate a new IV according to C0 ^ plaintext = new_iv ^ test_padding
        # thus new_iv = C0 ^ plaintext ^ test_padding

        # pad before the known plaintext with 0 to bring it up to a block
        ptext = bytearray(self.blk_size - len(self.p_text)) + self.p_text
        # generate a zero-message with new padding
        pad = bytearray(self.blk_size - pad_len) + bytearray([pad_len]*pad_len)

        # calculate and return the new_iv
        return bytearray([c ^ p ^ v for (c, p, v) in zip(self.c0, ptext, pad)])

    def fix_padding(self, new_iv: bytearray) -> int:
        pad_len = len(self.p_text) + 1

        # the tunable byte is the first byte of the new padding
        tune = self.blk_size - pad_len

        # try all possible value of the tunable byte
        for b in range(256):
            new_iv[tune] = b

            # until the new_iv leads to a valid padding
            if self.oracle(new_iv, self.c1):
                # i.e. new_iv[tune] ^ test_padding[tune] = c0[tune] ^ plain_text[tune]
                # <=>  b ^ pad_len = c0[tune] ^ plain_text[tune]
                # p.s. Here plain_text refers to the true plain_text and
                #      plain_text[tune] is exactly the byte revealed in this round

                # return the revealed byte
                return b ^ pad_len ^ self.c0[tune]


if __name__ == "__main__":
    # verify the command line parameters
    if len(sys.argv) != 3:
        print("Error: Run with wrong number of args", file=sys.stderr)
        print("Usage: python3 %s <c_0> <c_1>" % sys.argv[0], file=sys.stderr)
        print(sys.argv)
        exit(-1)

    # read the server address
    HOST = "localhost"
    PORT = 5000

    f = open("oracle/port", "r")
    lines = f.readlines()
    PORT = int(lines[0].strip())

    # initialize an oracle and an attack instance
    oracle = PaddingOracle(HOST, PORT)
    attack = PaddingOracleAttack(BLOCK_SIZE, oracle)

    # find the plaintext through padding oracle attack
    plaintext = attack(*map(
        lambda s: int(s, 16).to_bytes(BLOCK_SIZE, 'big'),
        sys.argv[1:]
    ))

    # print the result
    print(plaintext.decode('ascii'))
