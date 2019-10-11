#include "common.h"

int main(int argc, char const* argv[])
{
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* p = load_hex("F7E75FDC469067FFDC4E847C51F452DF");
    printBN("p = ", p);

    BIGNUM* q = load_hex("E85CED54AF57E53E092113E62F436F4F");
    printBN("q = ", q);

    BIGNUM* e = load_hex("0D88C3");
    printBN("e = ", e);

    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BIGNUM* totient = with_ctx2(BN_mul, p, q, ctx);
    printBN("totient = ", totient);

    BIGNUM* d = BN_mod_inverse(NULL, e, totient, ctx);
    printBN("d = ", d);

    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(totient);
    BN_free(d);

    BN_CTX_free(ctx);

    return 0;
}