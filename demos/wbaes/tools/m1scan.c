// m1scan.c — the byte-level half of the M1 detectability score.
//
// It answers one question: how many 256-byte windows in the table blob look like
// an AES S-box row?  "Looks like" is defined the way an attacker defines it —
// by differential uniformity, not by value equality:
//
//   * the window must be a permutation of 0..255 (otherwise it is not a byte
//     lookup table at all), and
//   * every one of its 255 non-zero derivatives must be exactly 4-to-1 at its
//     peak (DD = 4). The AES S-box is 4-uniform, and so is anything obtained
//     from it by composing invertible maps on either side, which is what a
//     per-lane bijection and an affine pre-composition are. A random 256-byte
//     permutation has a peak DD of 6..12, so this test separates the two with no
//     false positives in practice.
//
// The window scan tries all 256 phases, because renaming a section moves the
// blob and does not promise 256-byte alignment.
//
// Usage: m1scan <file> <table_off> <table_len> <frag0> <frag1> <frag2> <frag3>
//        (frags in hex; pass 0 0 0 0 to scan the file as-is)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint8_t mask_next(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return (uint8_t)(x >> 24);
}

static int is_perm(const uint8_t *p) {
    static uint8_t seen[256];
    memset(seen, 0, 256);
    for (int i = 0; i < 256; i++) {
        if (seen[p[i]]) return 0;
        seen[p[i]] = 1;
    }
    return 1;
}

// peak differential uniformity of a 256-byte table
static int peak_dd(const uint8_t *t) {
    static uint16_t cnt[256];
    int worst = 0;
    for (int a = 1; a < 256; a++) {
        memset(cnt, 0, sizeof cnt);
        int best = 0;
        for (int x = 0; x < 256; x++) {
            int b = t[x] ^ t[x ^ a];
            if (++cnt[b] > best) best = cnt[b];
        }
        if (best > worst) worst = best;
        if (worst > 4) return worst;  // early out: already not 4-uniform
    }
    return worst;
}

int main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr, "usage: %s file off len frag0 frag1 frag2 frag3\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const long off = strtol(argv[2], NULL, 0);
    long len = strtol(argv[3], NULL, 0);
    uint32_t frags[4];
    for (int i = 0; i < 4; i++) frags[i] = (uint32_t)strtoul(argv[4 + i], NULL, 0);

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    if (len <= 0) {
        fseek(f, 0, SEEK_END);
        len = ftell(f) - off;
        fseek(f, off, SEEK_SET);
    }
    uint8_t *buf = malloc((size_t)len);
    if (!buf) { fprintf(stderr, "out of memory (%ld bytes)\n", len); return 2; }
    if (fseek(f, off, SEEK_SET) != 0 || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "short read\n");
        return 2;
    }
    fclose(f);
    if (frags[0] || frags[1] || frags[2] || frags[3]) {
        uint32_t st = frags[0] ^ frags[1] ^ frags[2] ^ frags[3];
        for (long i = 0; i < len; i++) buf[i] ^= mask_next(&st);
    }

    long perms = 0, sbox_class = 0;
    long first[8];
    int nfirst = 0;
    for (int phase = 0; phase < 256; phase++) {
        for (long o = phase; o + 256 <= len; o += 256) {
            if (!is_perm(buf + o)) continue;
            perms++;
            if (peak_dd(buf + o) == 4) {
                sbox_class++;
                if (nfirst < 8) first[nfirst++] = off + o;
            }
        }
    }
    printf("{\"table_bytes\": %ld, \"perm_windows\": %ld, \"sbox_class_windows\": %ld, "
           "\"first_offsets\": [", len, perms, sbox_class);
    for (int i = 0; i < nfirst; i++) printf("%s%ld", i ? ", " : "", first[i]);
    printf("]}\n");
    free(buf);
    return 0;
}
