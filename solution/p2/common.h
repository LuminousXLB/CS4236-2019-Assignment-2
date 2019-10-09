#ifndef _CS4236_PROBLEM2_COMMON_BIGNUM_H_
#define _CS4236_PROBLEM2_COMMON_BIGNUM_H_

#include <iomanip>
#include <openssl/bn.h>
#include <sstream>
#include <stdio.h>

using std::hex;
using std::string;
using std::stringstream;
string to_hexstring(const string& str)
{
    stringstream ss;

    for (uint8_t c : str) {
        ss << hex << unsigned(c);
    }

    return ss.str();
}

string from_hexstring(const string& str)
{
    stringstream ss;

    for (auto it = str.begin(); it < str.end(); it += 2) {
        stringstream sub(string(it, it + 2));
        unsigned ch;
        sub >> hex >> ch;
        ss << uint8_t(ch);
    }

    return ss.str();
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