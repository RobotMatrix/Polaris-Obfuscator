// demo3: 模板 + 递归 + inline 展开 (mba/indcall/indbr)
// 验证: 模板实例化后的混淆 + 间接调用/跳转
#include <cstdio>
#include <cstdint>

template <typename T>
__attribute((__annotate__(("linearmba"))))
T tea_round(T v0, T v1, T key, int rounds) {
    T sum = 0;
    const T delta = 0x9e3779b9;
    for (int i = 0; i < rounds; i++) {
        sum += delta;
        v0 += ((v1 << 4) + key) ^ (v1 + sum) ^ ((v1 >> 5) + key);
        v1 += ((v0 << 4) + key) ^ (v0 + sum) ^ ((v0 >> 5) + key);
    }
    return v0 ^ v1;
}

__attribute((__annotate__(("indcall,indbr"))))
unsigned dispatch(unsigned x, unsigned k) {
    return tea_round<uint32_t>(x, k, 0x01234567, 16);
}

int main() {
    unsigned r1 = dispatch(0x12345678, 0x9abcdef0);
    unsigned r2 = dispatch(0x12345678, 0x9abcdef0);
    printf("dispatch=%08x deterministic=%s\n", r1, (r1 == r2) ? "yes" : "no");
    return 0;
}
