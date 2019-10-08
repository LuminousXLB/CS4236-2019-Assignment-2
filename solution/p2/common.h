#ifndef _CS4236_PROBLEM2_COMMON_BIGNUM_H_
#define _CS4236_PROBLEM2_COMMON_BIGNUM_H_

#include <openssl/bn.h>
#include <stdio.h>

/* 
 * Use BN_bn2hex(a) for hex string 
 * Use BN_bn2dec(a) for decimal string 
 */

void printBN(char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM* load_hex(const char* hex_string)
{
    BIGNUM* bn_ptr = BN_new();
    BN_hex2bn(&bn_ptr, hex_string);

    return bn_ptr;
}

BIGNUM* with_ctx2(int (*func)(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx), const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx)
{
    BIGNUM* result = BN_new();
    func(result, a, b, ctx);

    return result;
}

BIGNUM* with_ctx3(int (*func)(BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*), const BIGNUM* a, const BIGNUM* b, const BIGNUM* c, BN_CTX* ctx)
{
    BIGNUM* result = BN_new();
    func(result, a, b, c, ctx);

    return result;
}

#endif