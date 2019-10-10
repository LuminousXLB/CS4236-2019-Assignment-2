#include "common.h"

int main(int argc, char const* argv[])
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n = load_hex("AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BIGNUM* e = load_hex("010001");

    BIGNUM* M = load_hex(to_hexstring("Launch a missle.").c_str());

    {
        BIGNUM* S = load_hex("643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

        BIGNUM* M_ = with_ctx3(BN_mod_exp, S, e, n, ctx);

        printBN("Signature:        ", S);
        printBN("Original Message: ", M);
        printBN("Verified Message: ", M_);

        int result = BN_ucmp(M, M_);
        if (result == 0) {
            printf("%d: The signature is valid\n", result);
        } else {
            printf("%d: The signature is invalid\n", result);
        }
    }

    printf("\n");

    {
        BIGNUM* S = load_hex("643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

        BIGNUM* M_ = with_ctx3(BN_mod_exp, S, e, n, ctx);

        printBN("Signature:        ", S);
        printBN("Original Message: ", M);
        printBN("Verified Message: ", M_);

        int result = BN_ucmp(M, M_);
        if (result == 0) {
            printf("%d: The signature is valid\n", result);
        } else {
            printf("%d: The signature is invalid\n", result);
        }
    }

    BN_CTX_free(ctx);
    return 0;
}