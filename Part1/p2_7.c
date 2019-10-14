#include "p2_common.h"

BN_CTX* ctx = NULL;

int rsa_verify(BIGNUM* n, BIGNUM* e, BIGNUM* m, BIGNUM* s)
{
    /* recover the measurement */
    BIGNUM* M = with_ctx3(BN_mod_exp, s, e, n, ctx);
    printBN("[*] recovered: ", M);
    /* compare the input measurement against the recovered measurement */
    int r = BN_ucmp(M, m);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(M);
    return r == 0;
}

void verify(BIGNUM* n, BIGNUM* e, const char* message, const char* signature)
{

    /* load message from a ascii-encoded string */
    char message_hex[BUFFER_SIZE];
    to_hexstring(message, message_hex);
    BIGNUM* M = load_hex(message_hex);
    printf("Message:        %s\n", message);
    printBN("Message (hex): ", M);

    /* load signature from a string in hex format */
    BIGNUM* S = load_hex(signature);
    printBN("Signature:     ", S);

    /* verify the signature */
    int result = rsa_verify(n, e, M, S);
    if (result) {
        puts("Successfully verified");
    } else {
        puts("Verification failed");
    }

    /* free the components of the BIGNUM and the structure itself */
    BN_free(M);
    BN_free(S);
}

int main(int argc, char const* argv[])
{
    /* allocate and initialize a BN_CTX structure */
    ctx = BN_CTX_new();

    /* load rsa parameters form strings in hex format */
    BIGNUM* n = load_hex("AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BIGNUM* e = load_hex("010001");

    /* verify the signature */
    const char* msg = "Launch a missile.";
    char sig[] = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
    verify(n, e, msg, sig);

    printf("\n");

    /* modify the signature and verify again */
    sig[62] = '3';
    verify(n, e, msg, sig);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(n);
    BN_free(e);

    /* free the components of the BN_CTX and the structure itself */
    BN_CTX_free(ctx);
    return 0;
}