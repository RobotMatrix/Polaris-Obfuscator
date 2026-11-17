// test_dfa.cpp — DFA 故障注入模拟: 改表字节 → 预期输出垃圾/失配 (防护验证)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

static int fails = 0;
static uint8_t pt[16], ct_ok[16];

// WB 表故障: 全 9 轮 × 全 kk/j × 值域 0..15 (WB_PLAN 乱序 → 必须覆盖 plan 全空间)
static void test_wb_fault(void) {
    if (getenv("DFA_SKIP_WB")) { printf("[DFA table-fault WB] SKIP\n"); return; }
    static WBAES wb2;
    wb2.init();
    uint8_t ct_ref[16];
    wb2.encrypt(pt, ct_ref);
    for (int r = 0; r < 9; r++)
        for (int kk = 0; kk < 4; kk++)
            for (int j = 0; j < 4; j++)
                for (int x = 0; x < 16; x++)
                    wb2.t1.WB[r][kk][j][x] ^= 0xFFFFFFFFu;
    uint8_t ct_fault[16];
    wb2.encrypt(pt, ct_fault);
    int differs = memcmp(ct_fault, ct_ref, 16) != 0;
    uint8_t dec_fault[16];
    wb2.decrypt(ct_fault, dec_fault);
    int not_plain = memcmp(dec_fault, pt, 16) != 0;
    int ok = differs && not_plain;
    printf("[DFA table-fault WB] %s (differs=%d, not_plain=%d)\n",
           ok ? "PASS" : "FAIL", differs, not_plain);
    if (!ok) fails++;
}

// TF 表故障: 全值域 256 翻转 (末轮状态 9 轮雪崩 → 索引不可预知)
static void test_tf_fault(void) {
    static WBAES wb3;
    wb3.init();
    uint8_t ct_ref[16];
    wb3.encrypt(pt, ct_ref);
    // 每表项不同掩码 — 模拟真实故障注入 (等量翻转会自抵消: 列内 4 表 XOR 合并)
    for (int kk = 0; kk < 4; kk++)
        for (int j = 0; j < 4; j++)
            for (int x = 0; x < 256; x++)
                wb3.t1.TF[kk][j][x] ^= (uint32_t)(0x04030201u + (uint32_t)kk * 0x01010101u + (uint32_t)(x << 2));
    // instrument: fault 后双轨解密值 (t1 应乱, t2 应正)
    printf("  t1.TF ptr=%p t2.TF ptr=%p\n",
           (void *)&wb3.t1.TF[0][0][0], (void *)&wb3.t2.TF[0][0][0]);
    printf("  t1.TF[0][0][0]=%08x t2.TF[0][0][0]=%08x\n",
           wb3.t1.TF[0][0][0], wb3.t2.TF[0][0][0]);
    uint8_t ct_fault[16];
    wb3.encrypt(pt, ct_fault);
    int differs = memcmp(ct_fault, ct_ref, 16) != 0;
    uint8_t dec_fault[16];
    wb3.decrypt(ct_fault, dec_fault);
    int not_plain = memcmp(dec_fault, pt, 16) != 0;
    int ok = differs && not_plain;
    // 决定实验: fault 后手动 dec t1/t2 的 TF[0][0][0]:
    uint32_t d1 = WBAESTables::dec(&wb3.t1.TF[0][0][0], wb3.t1.session_half_a, 1);
    uint32_t d2 = WBAESTables::dec(&wb3.t2.TF[0][0][0], wb3.t2.session_half_a, 1);
    printf("  manual dec: t1=%08x t2=%08x (t1 should differ from pre-fault plain)\n", d1, d2);
    printf("[DFA table-fault TF] %s (differs=%d, not_plain=%d)\n",
           ok ? "PASS" : "FAIL", differs, not_plain);
    if (!ok) fails++;
}

// decoy 陷阱: 全 DECOY[0][*] 毒化 → 抽查命中 di=0 → 全局毒化 → 后续输出全垃圾
static void test_decoy(void) {
    static WBAES wb4;
    wb4.init();
    volatile uint8_t *dz = (volatile uint8_t *)&wb4.t1.DECOY[0][0];
    for (int k = 0; k < 2048; k++) dz[k] ^= 0x10;   // DECOY[0..1][*] 全翻 (di 命中率 1/8)
    int poisoned = 0;
    uint8_t o2[16];
    // 运行期抽查下标走系统熵源 (不可预测), 256 次重试 → 漏检率 (7/8)^256 ≈ 5e-15
    for (int k = 0; k < 256; k++) {
        wb4.encrypt(pt, o2);
        if (memcmp(o2, ct_ok, 16) != 0) { poisoned = 1; break; }
    }
    int ok = poisoned;
    printf("[DFA decoy-poison] %s (poisoned=%d)\n", ok ? "PASS" : "FAIL", poisoned);
    if (!ok) fails++;
}

int main(void) {
    static WBAES wb;
    wb.init();
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)i;
    wb.encrypt(pt, ct_ok);

    // 0. 基线
    {
        uint8_t back[16];
        wb.decrypt(ct_ok, back);
        bool ok = memcmp(back, pt, 16) == 0;
        printf("[DFA baseline roundtrip] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    test_wb_fault();
    test_tf_fault();
    test_decoy();

    printf(fails ? "DFA TOTAL: %d FAILS\n" : "DFA TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
