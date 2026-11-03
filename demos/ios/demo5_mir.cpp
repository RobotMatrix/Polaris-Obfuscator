// demo5: MIR backend 混淆主测 (asm 标记, 非 EH 函数)
// 验证: AArch64 ARMRubbishCode 在 iOS 目标上的完整流程
#include <cstdio>
#include <cstdint>

__attribute((__annotate__(("sub,bcf,fla"))))
uint32_t checksum(const uint8_t *data, uint32_t len) {
    asm("backend-obfu");
    uint32_t crc = 0xFFFFFFFF;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

int main() {
    const uint8_t payload[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                               0x69, 0x4f, 0x53, 0x21}; // "Hello iOS!"
    uint32_t c1 = checksum(payload, sizeof(payload));
    uint32_t c2 = checksum(payload, sizeof(payload));
    printf("crc=%08x stable=%s\n", c1, (c1 == c2) ? "yes" : "no");
    return 0;
}
