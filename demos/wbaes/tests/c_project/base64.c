#include "base64.h"
static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t b64_encode(const uint8_t *in, size_t len, char *out) {
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = (in[i]<<16)|(in[i+1]<<8)|in[i+2];
        out[j++] = b64c[(v>>18)&0x3F]; out[j++] = b64c[(v>>12)&0x3F];
        out[j++] = b64c[(v>>6)&0x3F]; out[j++] = b64c[v&0x3F];
    }
    if (i < len) {
        uint32_t v = in[i] << 16;
        if (i+1 < len) v |= in[i+1] << 8;
        out[j++] = b64c[(v>>18)&0x3F]; out[j++] = b64c[(v>>12)&0x3F];
        out[j++] = (i+1 < len) ? b64c[(v>>6)&0x3F] : '=';
        out[j++] = '=';
    }
    out[j] = 0;
    return j;
}
static int b64idx(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
size_t b64_decode(const char *in, uint8_t *out) {
    size_t j = 0;
    uint32_t v = 0; int bits = 0;
    while (*in) {
        if (*in == '=') break;
        int idx = b64idx(*in++);
        if (idx < 0) continue;
        v = (v << 6) | idx; bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (v >> bits) & 0xFF; }
    }
    return j;
}
