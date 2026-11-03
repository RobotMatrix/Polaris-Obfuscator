#ifndef BASE64_H
#define BASE64_H
#include <stdint.h>
#include <stddef.h>
size_t b64_encode(const uint8_t *in, size_t len, char *out);
size_t b64_decode(const char *in, uint8_t *out);
#endif
