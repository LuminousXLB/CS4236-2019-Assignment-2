#include "p2_common.h"

BN_CTX* ctx = NULL;

BIGNUM* calculate_private_exponent(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
    /* calculate the totient from p and q */
    BIGNUM* P = BN_dup(p);
    BN_sub_word(P, 1); // p' = p-1
    BIGNUM* Q = BN_dup(q);
    BN_sub_word(Q, 1); // q' = q-1
    BIGNUM* totient = with_ctx2(BN_mul, P, Q, ctx); // totient = p'*q'

    /* calculate the private key exponent d */
    BIGNUM* d = BN_mod_inverse(NULL, e, totient, ctx); // d = e^(-1) mod totient

    /* free the components of the BIGNUM and the structure itself */
    BN_free(P);
    BN_free(Q);
    BN_free(totient);
    return d;
}

int main(int argc, char const* argv[])
{
    /* allocate and initialize a BN_CTX structure */
    ctx = BN_CTX_new();

    /* load rsa parameters form strings in hex format */
    BIGNUM* p = load_hex("F7E75FDC469067FFDC4E847C51F452DF");
    BIGNUM* q = load_hex("E85CED54AF57E53E092113E62F436F4F");
    BIGNUM* e = load_hex("0D88C3");
    printBN("p = ", p);
    printBN("q = ", q);
    printBN("e = ", e);

    /* calculate private exponent d */
    BIGNUM* d = calculate_private_exponent(p, q, e);
    printBN("d = ", d);

    /* free the components of the BIGNUM and the structure itself */
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(d);

    /* free the components of the BN_CTX and the structure itself */
    BN_CTX_free(ctx);

    return 0;
}