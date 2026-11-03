#include "bignum.h"
#include <string.h>
void bn_zero(struct BigNum *a) { memset(a->w, 0, sizeof(a->w)); }
void bn_copy(struct BigNum *d, const struct BigNum *s) { memcpy(d->w, s->w, sizeof(s->w)); }
void bn_from_bytes(struct BigNum *a, const uint8_t *bytes) {
    for (int i = 0; i < BN_WORDS; i++) {
        a->w[i] = ((uint32_t)bytes[i*4]<<24)|((uint32_t)bytes[i*4+1]<<16)|
                  ((uint32_t)bytes[i*4+2]<<8)|bytes[i*4+3];
    }
}
void bn_to_bytes(const struct BigNum *a, uint8_t *bytes) {
    for (int i = 0; i < BN_WORDS; i++) {
        bytes[i*4] = (uint8_t)(a->w[i]>>24);
        bytes[i*4+1] = (uint8_t)(a->w[i]>>16);
        bytes[i*4+2] = (uint8_t)(a->w[i]>>8);
        bytes[i*4+3] = (uint8_t)a->w[i];
    }
}
void bn_xor(struct BigNum *d, const struct BigNum *a, const struct BigNum *b) {
    for (int i = 0; i < BN_WORDS; i++) d->w[i] = a->w[i] ^ b->w[i];
}
void bn_add_word(struct BigNum *a, uint32_t w) {
    uint64_t carry = w;
    for (int i = BN_WORDS-1; i >= 0 && carry; i--) {
        carry += a->w[i];
        a->w[i] = (uint32_t)carry;
        carry >>= 32;
    }
}
int bn_is_zero(const struct BigNum *a) {
    for (int i = 0; i < BN_WORDS; i++) if (a->w[i]) return 0;
    return 1;
}
int bn_cmp(const struct BigNum *a, const struct BigNum *b) {
    for (int i = 0; i < BN_WORDS; i++) {
        if (a->w[i] < b->w[i]) return -1;
        if (a->w[i] > b->w[i]) return 1;
    }
    return 0;
}
