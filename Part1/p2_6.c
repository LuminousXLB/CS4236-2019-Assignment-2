#include "p2_common.h"

BN_CTX* ctx = NULL;

BIGNUM* RSA_sign(BIGNUM* n, BIGNUM* d, BIGNUM* m)
{
    return with_ctx3(BN_mod_exp, m, d, n, ctx);
}

void sign(BIGNUM* n, BIGNUM* d, const char* message)
{
    /* load message from a ascii-encoded string */
    char message_hex[BUFFER_SIZE];
    to_hexstring(message, message_hex);
    BIGNUM* M = load_hex(message_hex);
    printf("Message:        %s\n", message);
    printBN("Message (hex): ", M);

    /* sign the message */
    BIGNUM* S = RSA_sign(n, d, M);
    printBN("Signature:     ", S);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(M);
    BN_free(S);
}

int main(int argc, char const* argv[])
{
    /* allocate and initialize a BN_CTX structure */
    ctx = BN_CTX_new();

    /* load rsa parameters form strings in hex format */
    BIGNUM* n = load_hex("DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BIGNUM* d = load_hex("74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    /* sign the message*/
    sign(n, d, "I owe you $2000.");
    printf("\n");
    sign(n, d, "I owe you $3000.");

    /* free the components of the BIGNUM and the structure itself */
    BN_free(n);
    BN_free(d);

    /* free the components of the BN_CTX and the structure itself */
    BN_CTX_free(ctx);
    return 0;
}
