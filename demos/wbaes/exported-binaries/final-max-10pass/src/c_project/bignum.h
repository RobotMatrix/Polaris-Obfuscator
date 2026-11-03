#ifndef BIGNUM_H
#define BIGNUM_H
#include <stdint.h>
#define BN_WORDS 8   // 256-bit
struct BigNum { uint32_t w[BN_WORDS]; };
void bn_zero(struct BigNum *a);
void bn_copy(struct BigNum *dst, const struct BigNum *src);
void bn_from_bytes(struct BigNum *a, const uint8_t *bytes);
void bn_to_bytes(const struct BigNum *a, uint8_t *bytes);
void bn_xor(struct BigNum *dst, const struct BigNum *a, const struct BigNum *b);
void bn_add_word(struct BigNum *a, uint32_t w);
int bn_is_zero(const struct BigNum *a);
int bn_cmp(const struct BigNum *a, const struct BigNum *b);
#endif
