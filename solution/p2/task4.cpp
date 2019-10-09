#include "common.h"

int main(int argc, char const* argv[])
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n = load_hex("DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BIGNUM* e = load_hex("010001");
    BIGNUM* d = load_hex("74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BIGNUM* M = load_hex(to_hexstring("A top secret!").c_str());
    BIGNUM* C = with_ctx3(BN_mod_exp, M, e, n, ctx);
    printBN("Ciphertext: ", C);

    BN_CTX_free(ctx);
    return 0;
}
