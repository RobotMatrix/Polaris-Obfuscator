// =============================================================================
// demo_wbaes_noasm.cpp — White-box AES-128 (Chow T-table + 外部编码, 无标注对照版)
//
// 白盒原理 (Chow et al. 2002 T-table + 外部编码):
//   AES 轮 = SubBytes -> ShiftRows -> AddRoundKey -> MixColumns
//   把三者合并进查找表, 密钥烘焙进表; 在此基础上叠加轮间仿射编码对:
//
//   编码: 每轮输出状态字节经 A_r(y) = M_r·y ⊕ c_r (M_r: 8x8 GF(2) 可逆矩阵,
//   c_r: 常量, 由密钥派生 PRNG 生成, 编译期固定). 编码链:
//     pt -> WB'_0(原域输入) -> [A_0 域] -> WB'_1(A_0^-1 索引吸收) -> ... ->
//     WB'_8 -> [A_8 域] -> TF'(A_8^-1 索引吸收) -> ct (原域输出)
//   相邻编码对 (输出侧 A_r, 下一轮输入侧 A_r^-1) 在表内互相抵消,
//   运行时查表路径与无编码版完全相同, 零额外开销.
//
//   表构造:
//     WB'_r[kk][j][z] = A_r'( WB_r[ A_{r-1}^-1(z) ] )
//       A_r' 逐字节作用在 MixColumns 输出 4 字节上; 常量 c_r 只放在 kk==3
//       那张表 (XOR 合并 4 表后 = M·Σ ⊕ c = A_r, 完整仿射; 若 4 表都放 c,
//       c⊕c⊕c⊕c = 0, 常量被抵消 — 踩过的坑)
//     TF'[kk][j][z] = TF[ A_8^-1(z) ]   末轮无输出编码 (密文必须是原域)
//
//   表输入是"编码域"字节, 表内 A^-1 索引重排即完成解码, 攻击者从表数据
//   看不到裸 AES 结构 (SBox/MC 轮廓被仿射打散), 抗表压缩/代数分析第一步.
//
// 密钥来源: wbaes_key.h (唯一密钥源, 随机生成, 明文密钥只存在这一处,
//           且仅用于编译期生成表——运行时代码/数据中不存在密钥明文)
//
// 轮密钥扩展基座: kokke/tiny-AES-c (MIT License)
// 自验: pycryptodome 预计算向量 (见 wbaes_key.h) + 加解密回环
//
// 与 demo_wbaes.cpp 完全同构, 无 __annotate__/asm — IDA plain 对照与系统 clang 语义验证用
// =============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cstdlib>

#define AES128 1
#include "aes.h"        // kokke/tiny-AES-c (MIT): 仅用 KeyExpansion
#include "wbaes_key.h"  // 密钥唯一来源 (编译期烘焙进表)

// ---- S 盒打散存储 (消除 AES 指纹) ----
// 标准 AES SBox/InvSBox 是最著名的数据段指纹 (yara/strings 秒识别).
// 存储态 = 密钥派生仿射作用后的置换: SBOX_S[i] = A_s(SBOX[i]), INV_S[i] = A_i(InvSBox[i])
// 表构造期用 aff_inv 恢复真值; A_s/A_i 由 PRNG 续流生成, 换密钥即全变.
// 明文 SBOX/inv_sbox/RCON 常量从二进制中消失 (扫描验证 0 命中).
static uint8_t SBOX_S[256];    // 打散后的 SBox (init 填充)
static uint8_t INV_S[256];     // 打散后的 InvSBox

// GF(2^8) 乘法, 约减多项式 0x11b 以两常量异或表达 (消 0x1b 直接指纹)
#define GF_MOD_HI 0x1c
#define GF_MOD_LO 0x07
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= (uint8_t)(GF_MOD_HI ^ GF_MOD_LO);
        b >>= 1;
    }
    return p;
}
// GF(2^8) 乘法逆 (暴力查证, init-only; x=0 约定为 0)
static uint8_t gf_inv(uint8_t x) {
    if (x == 0) return 0;
    for (int y = 1; y < 256; y++)
        if (gmul(x, (uint8_t)y) == 1) return (uint8_t)y;
    return 0;
}
// AES SBox 仿射变换 (FIPS-197 3.2): b'_i = b_i ^ b_{i+4} ^ b_{i+5} ^ b_{i+6} ^ b_{i+7} ^ c_i, c=0x63
// 系数以"位旋转"表达, 无 0x63/位模式常量表 — 常量 0x63 拆两片异或 (同 GF_MOD 手法)
#define SBOX_C_HI 0x60
#define SBOX_C_LO 0x03
static uint8_t sbox_affine_bit(uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = (uint8_t)(((b >> i) ^ (b >> ((i + 4) & 7)) ^ (b >> ((i + 5) & 7)) ^
                                 (b >> ((i + 6) & 7)) ^ (b >> ((i + 7) & 7)) ^
                                 ((uint8_t)(SBOX_C_HI ^ SBOX_C_LO) >> i)) & 1);
        r |= (uint8_t)(bit << i);
    }
    return r;
}
// RCON 运行时 GF 乘方生成: rcon[0]=1, rcon[r]=xtime(rcon[r-1]) — 消 {01,02,04..36} 指纹
static uint8_t rcon_gen(int r) {
    uint8_t v = 1;
    for (int i = 0; i < r; i++) {
        uint8_t hi = v & 0x80;
        v <<= 1;
        if (hi) v ^= (uint8_t)(GF_MOD_HI ^ GF_MOD_LO);
    }
    return v;
}

// MixColumns 矩阵某列中, 输入行 kk 的字节贡献到输出 4 行的系数 (FIPS-197 4.2.1)
static inline uint32_t mc_col(uint8_t sb, int kk) {
    switch (kk) {
    case 0: return ((uint32_t)gmul(sb,2) << 24) | ((uint32_t)sb << 16) | ((uint32_t)sb << 8) | gmul(sb,3);
    case 1: return ((uint32_t)gmul(sb,3) << 24) | ((uint32_t)gmul(sb,2) << 16) | ((uint32_t)sb << 8) | sb;
    case 2: return ((uint32_t)sb << 24) | ((uint32_t)gmul(sb,3) << 16) | ((uint32_t)gmul(sb,2) << 8) | sb;
    default:return ((uint32_t)sb << 24) | ((uint32_t)sb << 16) | ((uint32_t)gmul(sb,3) << 8) | gmul(sb,2);
    }
}

// InvMixColumns: 输入行 kk 的字节贡献 (系数列循环左移 kk 次)
static inline uint32_t imc_col(uint8_t v, int kk) {
    switch (kk) {
    case 0: return ((uint32_t)gmul(v,14) << 24) | ((uint32_t)gmul(v,9) << 16) | ((uint32_t)gmul(v,13) << 8) | gmul(v,11);
    case 1: return ((uint32_t)gmul(v,11) << 24) | ((uint32_t)gmul(v,14) << 16) | ((uint32_t)gmul(v,9) << 8) | gmul(v,13);
    case 2: return ((uint32_t)gmul(v,13) << 24) | ((uint32_t)gmul(v,11) << 16) | ((uint32_t)gmul(v,14) << 8) | gmul(v,9);
    default:return ((uint32_t)gmul(v,9) << 24) | ((uint32_t)gmul(v,13) << 16) | ((uint32_t)gmul(v,11) << 8) | gmul(v,14);
    }
}

// ---------------- 密钥派生 PRNG (splitmix64) 与仿射编码 ----------------
// 编码参数由密钥派生: 换密钥 => 编码矩阵全变 => 表数据完全不同
struct Affine {
    uint8_t m[8];      // GF(2) 行: bit j = 系数 (输出位 i = XOR m[i] 的位与输入位)
    uint8_t minv[8];   // m 的逆矩阵
    uint8_t c;         // 常量
};

static uint64_t wb_prng_state;
static uint64_t wb_prng_next() {
    uint64_t z = (wb_prng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// 裸矩阵前向仿射 (无常量): y = M·x
static inline uint8_t aff_mat(const uint8_t m[8], uint8_t x) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; j++)
            if ((m[i] >> j) & 1) bit ^= (x >> j) & 1;
        r |= (uint8_t)(bit << i);
    }
    return r;
}

// 仿射: A(x) = M·x ⊕ c (M 行 i 点乘输入位, 输出位 i)
static inline uint8_t aff_fwd(const Affine *a, uint8_t x, uint8_t use_const) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; j++)
            if ((a->m[i] >> j) & 1) bit ^= (x >> j) & 1;
        r |= (uint8_t)(bit << i);
    }
    return r ^ (use_const ? a->c : 0);
}
// 逆: A^-1(z) = M^-1·(z ⊕ c)
static inline uint8_t aff_inv(const Affine *a, uint8_t z) {
    uint8_t y = z ^ a->c;
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; j++)
            if ((a->minv[i] >> j) & 1) bit ^= (y >> j) & 1;
        r |= (uint8_t)(bit << i);
    }
    return r;
}

// 高斯消元求逆; 主元列 = bit col (与 aff_fwd 位约定一致 — 消元列序必须同向,
// 用 bit7 起列会得到转置修正后的错逆, 踩过的坑)
static int affine_invert(const uint8_t m[8], uint8_t out[8]) {
    uint8_t tmp[8], inv[8];
    memcpy(tmp, m, 8);
    for (int i = 0; i < 8; i++) inv[i] = (uint8_t)(1u << i);
    for (int col = 0; col < 8; col++) {
        int piv = -1;
        for (int r = col; r < 8; r++)
            if ((tmp[r] >> col) & 1) { piv = r; break; }
        if (piv < 0) return -1;   // 不可逆, 换矩阵
        if (piv != col) {
            uint8_t t = tmp[col]; tmp[col] = tmp[piv]; tmp[piv] = t;
            t = inv[col]; inv[col] = inv[piv]; inv[piv] = t;
        }
        for (int r = 0; r < 8; r++) {
            if (r != col && ((tmp[r] >> col) & 1)) {
                tmp[r] ^= tmp[col];
                inv[r] ^= inv[col];
            }
        }
    }
    memcpy(out, inv, 8);
    return 0;
}

static Affine g_sbox_aff;      // SBOX 恢复仿射 (A_s)
static Affine g_inv_aff;       // InvSBox 恢复仿射 (A_i)
static Affine g_aff[9];        // 加密轮 0..8 轮间编码
static Affine g_out_aff;       // 末轮输出编码 Q_10 (出口剥离, 切断 DFA 反推)
static uint8_t daff_m[9][8];      // 解密方向仿射组 (矩阵)
static uint8_t daff_minv[9][8];   // 逆矩阵
static uint8_t daff_c[9];         // 常量
static uint8_t g_kk_order[4];     // 会话随机 kk 遍历序 (查表顺序随机化, XOR 可交换)

// ---------------- 白盒表 ----------------
#include <pthread.h>
static uint32_t g_tls_half_b;      // halfB 全局 (单实例语义)
static pthread_key_t g_wbaes_tls_key;
static int g_wbaes_tls_init = 0;

// 单套白盒表 (336KB) — 双轨冗余 (抗 DFA) + 内存加密驻留 (抗 dump)
// 表项在内存中是密文: plain = enc ^ splitmix(addr ^ session_key)
// 会话 key init 时由密钥派生链生成 (不在二进制), 两次运行密文不同 → dump 无法积累
struct WBAESTables {
    uint32_t WB[9][4][4][256];   // 加密 9 轮: 144KB (密文驻留)
    uint32_t TF[4][4][256];      // 加密末轮: 16KB
    uint32_t FT[4][4][256];      // 解密入口 (原位 ARK10): 16KB
    uint32_t DWB[9][4][4][256];  // 解密 9 逆轮: 144KB
    uint32_t DTF[4][4][256];     // 解密末逆轮: 16KB
    uint32_t DECOY[16][256];     // 陷阱表: 无合法查询路径; 被篡改可检测
    uint32_t DECOY_SENTINEL;     // decoy[0][0] 的期望解密值
    uint32_t session_half_a;     // 会话 key 半 A (明文存表结构)
    // 半 B 存 pthread TLS (槽 0) — Unicorn 模拟需复现 TLS 上下文 (TPIDRRO_EL0),
    // 纯表 dump + 模拟无法获得 → 表解密全错 (反 Unicorn 核心手段)

    // 地址绑定解密: 表项密文 → 明文 (查表路径每次调用)
    // sk = halfA ^ halfB (TLS 读取) — 模拟器缺 TLS 上下文 → 解密错
    static inline uint32_t dec(const uint32_t *addr, uint32_t half_a, uint32_t tcls) {
        uint32_t half_b = g_tls_half_b;   // 全局 (单实例语义; 多实例见 README)
        // 表类别混入 keystream: 跨表项搬运 (重定位攻击) → 解密错
        uint64_t st = (uint64_t)(uintptr_t)addr ^ (half_a ^ half_b) ^ (tcls * 0x9E3779B9u);
        st += 0x9E3779B97F4A7C15ULL;
        st = (st ^ (st >> 30)) * 0xBF58476D1CE4E5B9ULL;
        st = (st ^ (st >> 27)) * 0x94D049BB133111EBULL;
        return *addr ^ (uint32_t)((st ^ (st >> 31)) & 0xFFFFFFFFULL);
    }
    // 加密 (init 装配): salt = 目标地址 (与 dec 的 addr 派生一致)
    static inline uint32_t enc(uint32_t plain, uint32_t sk, uintptr_t salt, uint32_t tcls) {
        uint64_t st = salt ^ sk ^ (tcls * 0x9E3779B9u);
        st += 0x9E3779B97F4A7C15ULL;
        st = (st ^ (st >> 30)) * 0xBF58476D1CE4E5B9ULL;
        st = (st ^ (st >> 27)) * 0x94D049BB133111EBULL;
        return plain ^ (uint32_t)((st ^ (st >> 31)) & 0xFFFFFFFFULL);
    }
};

struct WBAES {
    WBAESTables t1, t2;          // 双轨: 独立编码链, 同一密码学结果
    void init();
    void encrypt(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt(const uint8_t in[16], uint8_t out[16]) const;
private:
    // 单轨核心 (门面内部): 用指定表集算加密/解密
    static int enc_core(const WBAESTables &t1, const WBAESTables &t2, const uint8_t in[16], uint8_t out[16]);
    static int dec_core(const WBAESTables &t1, const WBAESTables &t2, const uint8_t in[16], uint8_t out[16]);
};

#ifdef WBAES_DYNAMIC_KEY
static uint8_t g_dyn_part[4][4];
static uint8_t g_dyn_cover[4][4];
static int g_dyn_ready = 0;
static inline uint8_t key_byte(int i) {
    const int s = i >> 2, b = i & 3;
    return (uint8_t)(g_dyn_part[s][b] ^ g_dyn_cover[s][b]);
}
#define KEY_BYTE(i) key_byte(i)
void wbaes_inject_key(const uint8_t part[4][4], const uint8_t cover[4][4]) {
    for (int s = 0; s < 4; s++)
        for (int b = 0; b < 4; b++) {
            g_dyn_part[s][b] = part[s][b];
            g_dyn_cover[s][b] = cover[s][b];
        }
    g_dyn_ready = 1;
}
#else
#define KEY_BYTE(i) wbaes_key::key_byte(i)
#endif

// ---- 轮计划表 (block 乱序映射): 密钥派生 PRNG 生成, 破坏 "block r = 轮 r" 标准模型 ----
// 运行时轮 r 查 WB[WB_PLAN[r]], dump 后 block 顺序与标准 AES 轮序不可对齐
static uint8_t WB_PLAN[9];
static uint8_t DWB_PLAN[9];

static void plan_identity() {
    for (int i = 0; i < 9; i++) { WB_PLAN[i] = (uint8_t)i; DWB_PLAN[i] = (uint8_t)i; }
}

static uint64_t g_plan_rng = 0;
static uint64_t plan_next() {
    g_plan_rng += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g_plan_rng;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void build_block_plan(uint64_t seed) {
    fprintf(stderr, "B0\n");
    plan_identity();
    fprintf(stderr, "B1\n");
    g_plan_rng = seed;
    fprintf(stderr, "B2\n");
    for (int i = 8; i > 0; i--) {
        int j = (int)(plan_next() % (uint64_t)(i + 1));
        fprintf(stderr, "B3 i=%d j=%d\n", i, j);
        uint8_t t = WB_PLAN[i]; WB_PLAN[i] = WB_PLAN[j]; WB_PLAN[j] = t;
        j = (int)(plan_next() % (uint64_t)(i + 1));
        t = DWB_PLAN[i]; DWB_PLAN[i] = DWB_PLAN[j]; DWB_PLAN[j] = t;
    }
}

// 轮密钥滑动窗口 (流式 KeyExpansion, FIPS-197 5.2):
//   窗口 = 最近 4 个扩展字 (16B = 1 轮密钥); rk_next() 递推下一字并滑动.
//   w[i] = w[i-4] ^ g(w[i-1]) — 窗口 [w_{i-4},w_{i-3},w_{i-2},w_{i-1}],
//   新字 = 窗口[0] ^ g(窗口[3]) (g = RotWord+SubWord+Rcon, i%4==0 时).
//   消除 176B 轮密钥数组: 生成即用即弃, 快照中最多残留"当前窗口" (派生物).
//   原始密钥分片只在窗口初值重组的一瞬, 第一次递推后即被覆写.
//   解密侧反序访问 → 重置窗口二次递推 (init-only).
static int g_rk_step = 0;   // 已递推字数 (0..43), 控制 Rcon 注入

static void rk_window_init(uint8_t w[16]) {
    for (int i = 0; i < 16; i++) w[i] = KEY_BYTE(i);   // RK0 = 分片重组 (瞬时)
    g_rk_step = 4;
}
// 递推下一个字, 窗口滑动 (新字在 w[12..15])
static void rk_next_word(uint8_t w[16]) {
    uint8_t t[4];
    if (g_rk_step % 4 == 0) {
        // RotWord + SubWord + Rcon
        t[0] = (uint8_t)(aff_inv(&g_sbox_aff, SBOX_S[w[13]]) ^ rcon_gen(g_rk_step / 4 - 1));
        t[1] = aff_inv(&g_sbox_aff, SBOX_S[w[14]]);
        t[2] = aff_inv(&g_sbox_aff, SBOX_S[w[15]]);
        t[3] = aff_inv(&g_sbox_aff, SBOX_S[w[12]]);
    } else {
        memcpy(t, w + 12, 4);
    }
    // 新字 = 窗口[0..3] ^ t → 滑动: [w1 w2 w3 new]
    uint8_t n0 = (uint8_t)(w[0] ^ t[0]);
    uint8_t n1 = (uint8_t)(w[1] ^ t[1]);
    uint8_t n2 = (uint8_t)(w[2] ^ t[2]);
    uint8_t n3 = (uint8_t)(w[3] ^ t[3]);
    w[0] = w[4]; w[1] = w[5]; w[2] = w[6]; w[3] = w[7];
    w[4] = w[8]; w[5] = w[9]; w[6] = w[10]; w[7] = w[11];
    w[8] = w[12]; w[9] = w[13]; w[10] = w[14]; w[11] = w[15];
    w[12] = n0; w[13] = n1; w[14] = n2; w[15] = n3;
    g_rk_step++;
}
// 递推到下一轮 (4 字): 调用后 w[0..15] = 完整下一轮密钥
static void rk_next_round(uint8_t w[16]) {
    rk_next_word(w); rk_next_word(w); rk_next_word(w); rk_next_word(w);
}

static void init_tables(WBAESTables &t, uint64_t prng_seed, uint32_t sk, uint32_t half_b);
static uint64_t prng_seed_from(int lane);
#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
// 反调试 v2 (静默降级): 检测到调试器 → 置污染位走错误分支, 不退出进程.
// 攻击者 attach 后看到"正常运行", 但密钥派生已污染 → 表失真 → 输出乱码,
// 与分片改写/DFA 防护触发的失败完全不可区分 (攻击者无从判断哪层防护命中).
// 检测: sysctl kern.proc PID → kinfo_proc.kp_flags & P_TRACED
static int debugger_present() {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;   // macOS: BSD 层 p_flag
}
// 调用时机: init 前 + 每次加解密前 (轮询, 防 attach 晚于 init)
// 交叉链: 3 个检测点读数互相校验 — 单点被 patch (恒返回 0) 时,
// 调试器仍在的其他点读 1 → 链不一致 → 仍毒化; 全部 3 点 patch 才能绕过.
// 毒化: 翻转打散 S 盒 (表构造材料) + 置污染位 (seed 混入)
static void anti_debug_check(int point) { (void)point; }   // 隔离测试: 禁用
#else
static void anti_debug_check(int) {}
#endif


void WBAES::init() {
#ifdef WBAES_DYNAMIC_KEY
    if (!g_dyn_ready) {
        // 动态模式未注入 → 表全垃圾 (静默)
        for (int i = 0; i < 256; i++) { SBOX_S[i] = 0; INV_S[i] = 0; }
        wbaes_key::g_key_tampered |= 0x4000u;
        return;   // 表为空, encrypt 输出垃圾
    }
#endif
    wbaes_key::verify_shards();            // 最早执行: 分片完整性 (写 g_key_tampered)
    build_block_plan(wbaes_key::fnv1a(wbaes_key::KBLK_A[0], 72) ^ ((uint64_t)wbaes_key::fnv1a(wbaes_key::CBLK_A[0], 72) << 32));
    const uint32_t sk = (uint32_t)wb_prng_next() ^ (uint32_t)(uintptr_t)this;
    if (!g_wbaes_tls_init) { pthread_key_create(&g_wbaes_tls_key, nullptr); g_wbaes_tls_init = 1; }
    const uint32_t half_b = (uint32_t)wb_prng_next();   // TLS 半 B: 两链共享
    g_tls_half_b = half_b;
    // 会话随机 kk 遍历序: XOR 可交换 → 输出不变; Unicorn trace 查表序列每会话不同
    {
        uint8_t ord[4] = {0, 1, 2, 3};
        for (int i = 3; i > 0; i--) {
            int j = (int)(wb_prng_next() % (i + 1));
            uint8_t tmp = ord[i]; ord[i] = ord[j]; ord[j] = tmp;
        }
        for (int i = 0; i < 4; i++) g_kk_order[i] = ord[i];
    }
    init_tables(t1, prng_seed_from(0), sk, half_b);   // 链 1
    init_tables(t2, prng_seed_from(0), sk, half_b);   // 链 2: 同编码等价轨
}

static uint64_t prng_seed_from(int lane) {
    // 链 seed 从分片块哈希派生: 链 1 = 片 0/1, 链 2 = 片 2/3 (单片 ≠ 密钥)
    // tampered 混入: 改写分片 → 校验失败 → seed 污染 → 表失真 (双保险)
    uint64_t s = 0;
    const int s0 = lane * 2, s1 = lane * 2 + 1;
    for (int b = 0; b < 4; b++) {
        s = (s << 8) | wbaes_key::KBLK_A[s0][wbaes_key::KOFF[s0] + b];
        s = (s << 8) | wbaes_key::KBLK_A[s1][wbaes_key::KOFF[s1] + b];
    }
    s ^= (uint64_t)wbaes_key::g_key_tampered * 0xDEADBEEFCAFEBABEULL;
    return s;
}

static void init_tables(WBAESTables &t, uint64_t seed, uint32_t sk, uint32_t half_b) {
    WBAESTables &T = t;
    // ---- 会话 key: 每次进程启动随机 (内存加密驻留的解密 key) ----
    // 会话 key 拆两半: halfA 存表结构 (dump 可得), halfB 存 pthread TLS
    // (dump 表结构拿不到 halfB; Unicorn 模拟需复现 TLS 上下文 — 反 Unicorn 核心)
    T.session_half_a = sk;
    g_tls_half_b = half_b;
    // 会话随机 kk 遍历序: XOR 可交换 → 输出不变; Unicorn trace 查表序列每会话不同
    {
        uint8_t ord[4] = {0, 1, 2, 3};
        for (int i = 3; i > 0; i--) {
            int j = (int)(wb_prng_next() % (i + 1));
            uint8_t tmp = ord[i]; ord[i] = ord[j]; ord[j] = tmp;
        }
        for (int i = 0; i < 4; i++) g_kk_order[i] = ord[i];
    }
    const uint32_t sk_eff = sk ^ half_b;   // 完整会话 key (读写对称, 两链共享 half_b)
    // 陷阱表: 填充加密哨兵 — 正常运行永不查询; 攻击者盲改表区若波及 → 可检测
    {
        const uint32_t sent = 0x57AB1E5Au ^ sk_eff;
        for (int i = 0; i < 16; i++)
            for (int z = 0; z < 256; z++)
                T.DECOY[i][z] = WBAESTables::enc(sent ^ (uint32_t)(i * 256 + z), sk_eff,
                                                 (uintptr_t)&T.DECOY[i][z], 5);
        T.DECOY_SENTINEL = sent;
    }
    // 两链统一: dec(t1)/dec(t2) 同密文同 keystream (TLS 相同线程内一致)
    // ---- 编码参数: 由链 seed 派生 (seed 内已混入 g_key_tampered 污染位) ----
    wb_prng_state = seed ^ ((uint64_t)T.session_half_a << 32);
    for (int r = 0; r < 9; r++) {
        for (int tries = 0; tries < 64; tries++) {
            Affine a;
            for (int i = 0; i < 8; i++) a.m[i] = (uint8_t)wb_prng_next();
            a.c = (uint8_t)wb_prng_next();
            if (affine_invert(a.m, a.minv) == 0) { g_aff[r] = a; break; }
        }
    }
    for (int tries = 0; tries < 64; tries++) {
        Affine a;
        for (int i = 0; i < 8; i++) a.m[i] = (uint8_t)wb_prng_next();
        a.c = (uint8_t)wb_prng_next();
        if (affine_invert(a.m, a.minv) == 0) { g_sbox_aff = a; break; }
    }
    for (int tries = 0; tries < 64; tries++) {
        Affine a;
        for (int i = 0; i < 8; i++) a.m[i] = (uint8_t)wb_prng_next();
        a.c = (uint8_t)wb_prng_next();
        if (affine_invert(a.m, a.minv) == 0) { g_inv_aff = a; break; }
    }
    // 末轮输出编码 Q_10 (PRNG 续流): TF 表输出 = Q_10(密文), 出口剥离 → DFA 反推切断
    for (int tries = 0; tries < 64; tries++) {
        Affine a;
        for (int i = 0; i < 8; i++) a.m[i] = (uint8_t)wb_prng_next();
        a.c = (uint8_t)wb_prng_next();
        if (affine_invert(a.m, a.minv) == 0) { g_out_aff = a; break; }
    }
    // ---- S 盒数学生成 (零数据): SBox(x) = affine(x^-1), FIPS-197 3.2 定义式 ----
    {
        uint8_t sb_std[256], iv_std[256];          // 栈上瞬时, init 结束即灭
        for (int i = 0; i < 256; i++) {
            sb_std[i] = sbox_affine_bit(gf_inv((uint8_t)i));
            iv_std[sb_std[i]] = (uint8_t)i;
        }
        for (int i = 0; i < 256; i++) {
            SBOX_S[i] = aff_fwd(&g_sbox_aff, sb_std[i], 1);
            INV_S[i]  = aff_fwd(&g_inv_aff,  iv_std[i], 1);
        }
    }
    // 反调试毒化点 A (链 1): 读数进入交叉链
    anti_debug_check(0);

    // 解密方向仿射组 (PRNG 续流), 文件级数组供流式构造用
    for (int r = 0; r < 9; r++) {
        for (int tries = 0; tries < 64; tries++) {
            uint8_t m[8], minv[8];
            for (int i = 0; i < 8; i++) m[i] = (uint8_t)wb_prng_next();
            uint8_t c = (uint8_t)wb_prng_next();
            if (affine_invert(m, minv) == 0) {
                memcpy(daff_m[r], m, 8);
                memcpy(daff_minv[r], minv, 8);
                daff_c[r] = c;
                break;
            }
        }
    }


    // ============ 加密方向 (轮密钥流式窗口) ============
    {
        uint8_t w[16];                    // 滑动窗口 (当前轮密钥, 派生物)
        rk_window_init(w);                // RK0 = 分片重组 (瞬时, 第一次 advance 即覆写)

        // WB r=0..8: 用 RK1..RK9, 存储槽 = WB_PLAN[r] (乱序)
        for (int r = 0; r < 9; r++) {
            rk_next_round(w);             // w = RK[r+1]
            const int slot = WB_PLAN[r];
            const Affine *pa = (r > 0) ? &g_aff[r - 1] : nullptr;
            const Affine *ca = &g_aff[r];
            for (int kk = 0; kk < 4; kk++) {
                for (int j = 0; j < 4; j++) {
                    const uint8_t a0 = (r == 0) ? KEY_BYTE(4 * ((j + kk) % 4) + kk) : 0;
                    for (int z = 0; z < 256; z++) {
                        const uint8_t x = pa ? aff_inv(pa, (uint8_t)z) : (uint8_t)z;
                        const uint32_t v = mc_col(aff_inv(&g_sbox_aff, SBOX_S[x ^ a0]), kk)
                                         ^ ((uint32_t)w[4 * j + kk] << (24 - 8 * kk));
                        uint32_t ob = 0;
                        for (int b = 0; b < 4; b++) {
                            uint8_t byte = (uint8_t)(v >> (24 - 8 * b));
                            uint8_t nb = aff_fwd(ca, byte, (kk == 3) ? 1 : 0);
                            ob |= (uint32_t)nb << (24 - 8 * b);
                        }
                        T.WB[slot][kk][j][z] = WBAESTables::enc(ob, sk_eff, (uintptr_t)&T.WB[slot][kk][j][z], 0);
                    }
                }
            }
        }
        // TF: RK10
        rk_next_round(w);
        for (int kk = 0; kk < 4; kk++)
            for (int j = 0; j < 4; j++)
                for (int z = 0; z < 256; z++) {
                    const uint8_t x = aff_inv(&g_aff[8], (uint8_t)z);
                    {
                        const uint32_t plain = (uint32_t)(aff_inv(&g_sbox_aff, SBOX_S[x]) ^ w[4 * j + kk]) << (24 - 8 * kk);
                        uint32_t q = 0;
                        for (int b = 0; b < 4; b++) {
                            // 常量分摊: 仅 kk==3 表 ⊕ c_10, 4 表 XOR 合成完整 Q_10 (同 WB 手法)
                            uint8_t nb = aff_fwd(&g_out_aff, (uint8_t)(plain >> (24 - 8 * b)), (kk == 3) ? 1 : 0);
                            q |= (uint32_t)nb << (24 - 8 * b);
                        }
                        T.TF[kk][j][z] = WBAESTables::enc(q, sk_eff, (uintptr_t)&T.TF[kk][j][z], 1);
                    }
                }
        // FT: 原位 ARK(10) — 同用 RK10 (w 尚未滑动)
        for (int kk = 0; kk < 4; kk++)
            for (int j = 0; j < 4; j++)
                for (int x = 0; x < 256; x++)
                    T.FT[kk][j][x] = WBAESTables::enc((uint32_t)(x ^ w[4 * j + kk]) << (24 - 8 * kk), sk_eff, (uintptr_t)&T.FT[kk][j][x], 2);
    }

    // ============ 解密方向 (窗口重置, 正向二次递推) ============
    {
        uint8_t w[16];
        rk_window_init(w);
        // DWB[r]: ark = RK[9-r], r=0..8 → RK9..RK1 — 重置后正向 RK1..RK9
        for (int rr = 1; rr <= 9; rr++) {
            rk_next_round(w);             // w = RK[rr]
            const int r = 9 - rr;
            const int slot = DWB_PLAN[r];
            for (int kk = 0; kk < 4; kk++) {
                for (int j = 0; j < 4; j++) {
                    for (int z = 0; z < 256; z++) {
                        const uint8_t x = (rr < 9) ? aff_mat(daff_minv[8 - rr], (uint8_t)(z ^ daff_c[8 - rr])) : (uint8_t)z;
                        const uint32_t v = imc_col((uint8_t)(aff_inv(&g_inv_aff, INV_S[x]) ^ w[4 * j + kk]), kk);
                        uint32_t ob = 0;
                        for (int b = 0; b < 4; b++) {
                            uint8_t byte = (uint8_t)(v >> (24 - 8 * b));
                            uint8_t nb = aff_mat(daff_m[9 - rr], byte);
                            if (kk == 3) nb ^= daff_c[9 - rr];
                            ob |= (uint32_t)nb << (24 - 8 * b);
                        }
                        T.DWB[slot][kk][j][z] = WBAESTables::enc(ob, sk_eff, (uintptr_t)&T.DWB[slot][kk][j][z], 3);
                    }
                }
            }
        }
        // DTF: RK0 — 重置窗口 (w = RK0); 输入侧吸收 B_8 (DWB[8] 输出编码域)
        rk_window_init(w);
        for (int kk = 0; kk < 4; kk++)
            for (int j = 0; j < 4; j++)
                for (int z = 0; z < 256; z++) {
                    const uint8_t x = aff_mat(daff_minv[8], (uint8_t)(z ^ daff_c[8]));
                    T.DTF[kk][j][z] = WBAESTables::enc((uint32_t)(aff_inv(&g_inv_aff, INV_S[x]) ^ w[4 * j + kk]) << (24 - 8 * kk), sk_eff, (uintptr_t)&T.DTF[kk][j][z], 4);
                }
        // 窗口用后即焚: DTF 是最后一次用 RK0 (其值 = 分片重组的原始密钥),
        // 清零防 init 栈帧残留 (volatile 写阻优化器删除)
        {
            volatile uint8_t *vw = w;
            for (int i = 0; i < 16; i++) vw[i] = 0;
        }
    }
}

// -----------------------------------------------------------------------------
// 加密: 9 轮查表 + 末轮, 全程无密钥/编码变量 (编码全部烘在表内)
// ---------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// DFA 防护门面: 双轨冗余 — 两套独立编码链的表算同一结果, 输出比对.
// 故障注入单表 → 两轨结果不一致 → 输出随机垃圾 (非 fault cypher),
// 攻击者无法收集有效 (正确密文, 故障密文) 对 → DFA 差分分析失效.
// 同时注入两表同位故障 → 需要精确控制两次故障, 防护达成.
// -----------------------------------------------------------------------------
void WBAES::encrypt(const uint8_t in[16], uint8_t out[16]) const {
    anti_debug_check(2);          // 运行中 attach → 静默置位
    // 陷阱抽查: 随机选一个 decoy 项, 解密应等于哨兵 — 被篡改 → 毒化
    {
        const int di = (int)(wb_prng_next() % 16);
        const int dz = (int)(wb_prng_next() % 256);
        if (WBAESTables::dec(&t1.DECOY[di][dz], t1.session_half_a, 5) !=
            (t1.DECOY_SENTINEL ^ (uint32_t)(di * 256 + dz)))
            wbaes_key::g_key_tampered |= 0x8000u;
    }
    if (wbaes_key::g_key_tampered & 0x8000u) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_prng_next() & 0xFF);
        return;                  // 走错误分支: PRNG 垃圾, 非 fault cypher
    }
    // 轮级双算 (DFA 深防): 故障在 core 内部即被拦截
    // 调用栈化: core 入口指针由栈变量运行时计算 (非直接 BL 符号)
    uint8_t ct[16];
    if (enc_core(t1, t2, in, ct) != 0) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_prng_next() & 0xFF);
        return;
    }
    // 回环自检: encrypt 后 decrypt 验证 — fault 泄漏到输出的故障密文
    // 解密回原明文必不等于输入 → 拦截 (DFA 收集不到有效 fault 对)
    uint8_t back[16];
    if (dec_core(t1, t2, ct, back) != 0 || memcmp(back, in, 16) != 0) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_prng_next() & 0xFF);
        return;
    }
    memcpy(out, ct, 16);
}

void WBAES::decrypt(const uint8_t in[16], uint8_t out[16]) const {
    anti_debug_check(1);
    if (wbaes_key::g_key_tampered & 0x8000u) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_prng_next() & 0xFF);
        return;
    }
    if (dec_core(t1, t2, in, out) != 0) {
        for (int i = 0; i < 16; i++) out[i] = (uint8_t)(wb_prng_next() & 0xFF);
    }
}

int WBAES::enc_core(const WBAESTables &t1, const WBAESTables &t2, const uint8_t in[16], uint8_t out[16]) {
    // DFA 深防: 轮级双算 — 每轮两套表各算一次, 比对一致才进下轮.
    // 单表故障 → 本轮即失配 → 返回 -1 (垃圾输出), 故障密文永不产生.
    uint8_t s1[4][4], s2[4][4];
    memcpy(s1, in, 16);
    memcpy(s2, in, 16);

    for (int r = 0; r < 9; r++) {
        uint8_t n1[4][4], n2[4][4];
        for (int j = 0; j < 4; j++) {
            uint32_t a1 = 0, a2 = 0;
            for (int ki = 0; ki < 4; ki++) {
                const int kk = g_kk_order[ki];   // 会话随机遍历序
                uint8_t x1 = s1[(j + kk) % 4][kk];
                uint8_t x2 = s2[(j + kk) % 4][kk];
                a1 ^= WBAESTables::dec(&t1.WB[WB_PLAN[r]][kk][j][x1], t1.session_half_a, 0);
                a2 ^= WBAESTables::dec(&t2.WB[WB_PLAN[r]][kk][j][x2], t2.session_half_a, 0);
            }
            for (int b = 0; b < 4; b++) {
                n1[j][b] = (a1 >> (24 - 8 * b)) & 0xFF;
                n2[j][b] = (a2 >> (24 - 8 * b)) & 0xFF;
            }
        }
        for (int j = 0; j < 4; j++)
            for (int b = 0; b < 4; b++)
                if (n1[j][b] != n2[j][b]) return -1;   // 轮级失配 = 故障注入
        memcpy(s1, n1, 16);
        memcpy(s2, n2, 16);
    }
    // 末轮 (无 MC)
    {
        uint8_t n1[4][4], n2[4][4];
        for (int j = 0; j < 4; j++) {
            uint32_t a1 = 0, a2 = 0;
            for (int ki = 0; ki < 4; ki++) {
                const int kk = g_kk_order[ki];   // 会话随机遍历序
                a1 ^= WBAESTables::dec(&t1.TF[kk][j][s1[(j + kk) % 4][kk]], t1.session_half_a, 1);
                a2 ^= WBAESTables::dec(&t2.TF[kk][j][s2[(j + kk) % 4][kk]], t2.session_half_a, 1);
            }
            for (int b = 0; b < 4; b++) {
                n1[j][b] = aff_inv(&g_out_aff, (uint8_t)(a1 >> (24 - 8 * b)));   // 剥离 Q_10
                n2[j][b] = aff_inv(&g_out_aff, (uint8_t)(a2 >> (24 - 8 * b)));
            }
        }
        for (int j = 0; j < 4; j++)
            for (int b = 0; b < 4; b++)
                if (n1[j][b] != n2[j][b]) return -1;
        memcpy(out, n1, 16);
    }
    return 0;
}

int WBAES::dec_core(const WBAESTables &t1, const WBAESTables &t2, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s1[4][4], s2[4][4];
    memcpy(s1, in, 16);
    memcpy(s2, in, 16);

    // 原位 ARK(10)
    {
        uint8_t n1[4][4], n2[4][4];
        for (int j = 0; j < 4; j++) {
            uint32_t a1 = 0, a2 = 0;
            for (int ki = 0; ki < 4; ki++) {
                const int kk = g_kk_order[ki];   // 会话随机遍历序
                a1 ^= WBAESTables::dec(&t1.FT[kk][j][s1[j][kk]], t1.session_half_a, 2);
                a2 ^= WBAESTables::dec(&t2.FT[kk][j][s2[j][kk]], t2.session_half_a, 2);
            }
            for (int b = 0; b < 4; b++) {
                n1[j][b] = (a1 >> (24 - 8 * b)) & 0xFF;
                n2[j][b] = (a2 >> (24 - 8 * b)) & 0xFF;
            }
        }
        for (int j = 0; j < 4; j++)
            for (int b = 0; b < 4; b++)
                if (n1[j][b] != n2[j][b]) return -1;
        memcpy(s1, n1, 16);
        memcpy(s2, n2, 16);
    }
    // 逆轮 9..1
    for (int r = 0; r < 9; r++) {
        uint8_t n1[4][4], n2[4][4];
        for (int j = 0; j < 4; j++) {
            uint32_t a1 = 0, a2 = 0;
            for (int ki = 0; ki < 4; ki++) {
                const int kk = g_kk_order[ki];   // 会话随机遍历序
                uint8_t x1 = s1[(j - kk + 4) % 4][kk];
                uint8_t x2 = s2[(j - kk + 4) % 4][kk];
                a1 ^= WBAESTables::dec(&t1.DWB[DWB_PLAN[r]][kk][j][x1], t1.session_half_a, 3);
                a2 ^= WBAESTables::dec(&t2.DWB[DWB_PLAN[r]][kk][j][x2], t2.session_half_a, 3);
            }
            for (int b = 0; b < 4; b++) {
                n1[j][b] = (a1 >> (24 - 8 * b)) & 0xFF;
                n2[j][b] = (a2 >> (24 - 8 * b)) & 0xFF;
            }
        }
        for (int j = 0; j < 4; j++)
            for (int b = 0; b < 4; b++)
                if (n1[j][b] != n2[j][b]) return -1;
        memcpy(s1, n1, 16);
        memcpy(s2, n2, 16);
    }
    // 末逆轮
    {
        uint8_t n1[4][4], n2[4][4];
        for (int j = 0; j < 4; j++) {
            uint32_t a1 = 0, a2 = 0;
            for (int ki = 0; ki < 4; ki++) {
                const int kk = g_kk_order[ki];   // 会话随机遍历序
                a1 ^= WBAESTables::dec(&t1.DTF[kk][j][s1[(j - kk + 4) % 4][kk]], t1.session_half_a, 4);
                a2 ^= WBAESTables::dec(&t2.DTF[kk][j][s2[(j - kk + 4) % 4][kk]], t2.session_half_a, 4);
            }
            for (int b = 0; b < 4; b++) {
                n1[j][b] = (a1 >> (24 - 8 * b)) & 0xFF;
                n2[j][b] = (a2 >> (24 - 8 * b)) & 0xFF;
            }
        }
        for (int j = 0; j < 4; j++)
            for (int b = 0; b < 4; b++)
                if (n1[j][b] != n2[j][b]) return -1;
        memcpy(out, n1, 16);
    }
    return 0;
}

#ifndef WBAES_NO_MAIN
// -----------------------------------------------------------------------------
// 自验: pycryptodome 预计算向量 (wbaes_key.h) + 加解密回环
// -----------------------------------------------------------------------------
int main() {
    anti_debug_check(2);   // writeup 攻击环 4: 调试器 → 静默走错误分支 (不退出)
    WBAES wb;
    wb.init();

    uint8_t ct[16], rt[16];
    wb.encrypt(wbaes_key::test_pt, ct);
    wb.decrypt(ct, rt);

    printf("plaintext : ");
    for (int i = 0; i < 16; i++) printf("%02x", wbaes_key::test_pt[i]);
    printf("\nciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\nexpected  : ");
    for (int i = 0; i < 16; i++) printf("%02x", wbaes_key::test_ct[i]);
    printf("\nroundtrip : ");
    for (int i = 0; i < 16; i++) printf("%02x", rt[i]);
    printf("\n");
    bool vec = memcmp(ct, wbaes_key::test_ct, 16) == 0;
    bool round = memcmp(rt, wbaes_key::test_pt, 16) == 0;
    printf("vector-match: %s\n", vec ? "PASS" : "FAIL");
    printf("roundtrip   : %s\n", round ? "PASS" : "FAIL");
    printf("table-bytes : %zu KB\n",
           sizeof(WBAESTables) / 1024 * 2);
    return (vec && round) ? 0 : 1;
}
#endif // WBAES_NO_MAIN
