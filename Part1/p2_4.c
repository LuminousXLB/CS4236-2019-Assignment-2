#include "p2_common.h"

BN_CTX* ctx = NULL;

BIGNUM* rsa_encrypt(BIGNUM* n, BIGNUM* e, BIGNUM* m)
{
    return with_ctx3(BN_mod_exp, m, e, n, ctx);
}

int main(int argc, char const* argv[])
{
    /* allocate and initialize a BN_CTX structure */
    ctx = BN_CTX_new();

    /* load rsa parameters form strings in hex format */
    BIGNUM* n = load_hex("DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BIGNUM* e = load_hex("010001");
    printBN("n = ", n);
    printBN("e = ", e);

    /* load message from a ascii-encoded string */
    char plaintext_hex[BUFFER_SIZE];
    to_hexstring("A top secret!", plaintext_hex);
    BIGNUM* M = load_hex(plaintext_hex);
    printBN("Plaintext: ", M);

    /* encrypt the message */
    BIGNUM* C = rsa_encrypt(n, e, M);
    printBN("Ciphertext: ", C);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(n);
    BN_free(e);
    BN_free(M);
    BN_free(C);

    /* free the components of the BN_CTX and the structure itself */
    BN_CTX_free(ctx);
    return 0;
}
