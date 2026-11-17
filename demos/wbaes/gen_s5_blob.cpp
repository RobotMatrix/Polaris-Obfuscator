// 生成烘焙二进制用的份额封存。只写文件，不打印密钥字节。
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#define WBAES_NO_DEVBIND 1
#include "wbaes_key.h"
#include "wbaes_s5_seal.h"

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur) return 3;
    uint8_t rnd[80];
    if (fread(rnd, 1, 80, ur) != 80) return 3;
    fclose(ur);

    uint8_t blob[80];
    for (int i = 0; i < 16; i++) {
        uint8_t key = wbaes_key::key_byte(i);
        uint8_t share0 = (uint8_t)(rnd[i] | 1);
        uint8_t share1 = (uint8_t)(share0 ^ key);
        uint8_t mask = rnd[16 + i];
        uint8_t dummy = rnd[32 + i];
        uint8_t flag = rnd[48 + i];
        if ((share0 ^ share1) != key) return 4;
        uint8_t *g = blob + i * 5;
        g[0] = mask;
        g[1] = (uint8_t)(share0 ^ mask ^ wbaes_s5_stream(i));
        g[2] = (uint8_t)(share1 ^ mask ^ wbaes_s5_stream(i + 16));
        g[3] = (uint8_t)(dummy ^ wbaes_s5_stream(i + 32));
        g[4] = (uint8_t)(flag ^ wbaes_s5_stream(i + 48));
        uint8_t back0 = (uint8_t)(g[1] ^ g[0] ^ wbaes_s5_stream(i));
        uint8_t back1 = (uint8_t)(g[2] ^ g[0] ^ wbaes_s5_stream(i + 16));
        if ((uint8_t)(back0 ^ back1) != key) return 5;
    }

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) return 6;
    fprintf(fp, "unsigned char kS5Blob[80] = {\n");
    for (int i = 0; i < 80; i++) {
        fprintf(fp, "0x%02x%s", blob[i], (i + 1) % 10 == 0 ? ",\n" : ",");
    }
    fprintf(fp, "};\n");
    fclose(fp);
    printf("seal-check PASS\nwrote %s\n", argv[1]);
    return 0;
}
