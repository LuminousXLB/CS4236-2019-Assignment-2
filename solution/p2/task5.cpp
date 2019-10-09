#include "common.h"

int main(int argc, char const* argv[])
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n = load_hex("DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BIGNUM* e = load_hex("010001");
    BIGNUM* d = load_hex("74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BIGNUM* C = load_hex("8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    BIGNUM* M = with_ctx3(BN_mod_exp, C, d, n, ctx);

    char* number_str = BN_bn2hex(M);
    printf("%s %s\n", "Plaintext: ", from_hexstring(number_str).c_str());
    OPENSSL_free(number_str);

    BN_CTX_free(ctx);
    return 0;
}
