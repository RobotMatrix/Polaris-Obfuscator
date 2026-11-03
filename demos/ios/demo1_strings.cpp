// demo1: 字符串加密 + 多函数 (gvenc/alias/sub/bcf)
// 验证: 全局字符串混淆 + alias access
#include <cstdio>
#include <cstring>

__attribute((__annotate__(("gvenc"))))
static const char SECRET[] = "iOS-Obfuscation-Test";

__attribute((__annotate__(("aliasaccess,substitution"))))
unsigned fnv1a(const char *s) {
    unsigned h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
        s++;
    }
    return h;
}

__attribute((__annotate__(("boguscfg,substitution"))))
void transform(char *buf, unsigned key) {
    size_t n = strlen(buf);
    for (size_t i = 0; i < n; i++)
        buf[i] ^= (char)(key >> ((i % 4) * 8));
}

int main() {
    char buf[64];
    strcpy(buf, SECRET);
    unsigned h1 = fnv1a(buf);
    transform(buf, 0xDEADBEEF);
    unsigned h2 = fnv1a(buf);
    transform(buf, 0xDEADBEEF); // 还原
    unsigned h3 = fnv1a(buf);
    printf("hash(plain)=%08x hash(enc)=%08x hash(restored)=%08x\n", h1, h2, h3);
    printf("restore_ok=%s\n", (h1 == h3) ? "yes" : "no");
    return 0;
}
