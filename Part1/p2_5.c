#include "p2_common.h"

BN_CTX* ctx = NULL;

BIGNUM* rsa_decrypt(BIGNUM* n, BIGNUM* d, BIGNUM* c)
{
    return with_ctx3(BN_mod_exp, c, d, n, ctx);
}

int main(int argc, char const* argv[])
{
    /* allocate and initialize a BN_CTX structure */
    ctx = BN_CTX_new();

    /* load rsa parameters form strings in hex format */
    BIGNUM* n = load_hex("DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BIGNUM* d = load_hex("74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("n = ", n);
    printBN("d = ", d);

    /* load ciphertext form strings in hex format */
    BIGNUM* C = load_hex("8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    printBN("Ciphertext: ", C);

    /* decrypt the message */
    BIGNUM* M = rsa_decrypt(n, d, C);

    /* print the message */
    char plaintext[BUFFER_SIZE];
    char* plaintext_hex = BN_bn2hex(M);
    from_hexstring(plaintext_hex, plaintext);
    printf("%s %s\n", "Plaintext: ", plaintext);
    OPENSSL_free(plaintext_hex);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(n);
    BN_free(d);
    BN_free(C);
    BN_free(M);

    /* free the components of the BN_CTX and the structure itself */
    BN_CTX_free(ctx);
    return 0;
}
