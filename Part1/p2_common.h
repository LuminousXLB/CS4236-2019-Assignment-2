#ifndef _CS4236_PROBLEM2_COMMON_BIGNUM_H_
#define _CS4236_PROBLEM2_COMMON_BIGNUM_H_

#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 4096

/*
 * Encoding translate between hex and ascii
 */

int to_hexstring(const char* in, char* out)
{
    size_t length = strlen(in);

    for (size_t i = 0; i < length; i++) {
        sprintf(out + 2 * i, "%x", (unsigned)in[i]);
    }
    return 0;
}

int from_hexstring(const char* in, char* out)
{
    size_t length = strlen(in);
    if (length % 2 != 0) {
        out[0] = '\0';
        return -1;
    }

    char buf[3];
    unsigned ch;

    for (size_t i = 0; i < length; i += 2) {
        strncpy(buf, in + i, 2);
        sscanf(buf, "%x", &ch);
        out[i / 2] = ch;
    }

    out[length / 2] = '\0';
    return 0;
}

/* 
 * Use BN_bn2hex(a) for hex string 
 * Use BN_bn2dec(a) for decimal string 
 */

void printBN(const char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

/*
 * Generate a BIGNUM from a hex string
 */

BIGNUM* load_hex(const char* hex_string)
{
    BIGNUM* bn_ptr = BN_new();
    BN_hex2bn(&bn_ptr, hex_string);

    return bn_ptr;
}

/*
 * Call a BIGNUM funtion operating on two big numbers and requiring a context
 */

BIGNUM* with_ctx2(int (*func)(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx),
    const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx)
{
    BIGNUM* result = BN_new();
    func(result, a, b, ctx);

    return result;
}

/*
 * Call a BIGNUM funtion operating on three big numbers and requiring a context
 */

BIGNUM* with_ctx3(int (*func)(BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*),
    const BIGNUM* a, const BIGNUM* b, const BIGNUM* c, BN_CTX* ctx)
{
    BIGNUM* result = BN_new();
    func(result, a, b, c, ctx);

    return result;
}

#endif
