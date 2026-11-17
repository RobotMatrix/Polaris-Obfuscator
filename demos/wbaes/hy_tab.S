// kHyTab 嵌入：gen_hybrid 生成的 hy_table.bin 原样进二进制。
// 编译时须能在 -I 路径或当前目录找到 hy_table.bin。
// Mach-O (macOS/iOS)。符号名带下划线前缀, 与 demo_wbaes.cpp 的
// extern "C" const uint8_t kHyTab[] 对应。
    .section __DATA,__hytab
    .align 4
    .globl _kHyTab
    .private_extern _kHyTab
_kHyTab:
    .incbin "hy_table.bin"
