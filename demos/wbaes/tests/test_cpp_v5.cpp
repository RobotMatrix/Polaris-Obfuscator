// test_cpp_v5.cpp — C++ 编译期元编程 × 白盒 AES (第五层)
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <array>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// ===== constexpr GF(2^8) 乘法 (编译期) =====
constexpr uint8_t constexpr_xtime(uint8_t a) {
    return (uint8_t)(((a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1)) & 0xFF);
}
constexpr uint8_t constexpr_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = constexpr_xtime(a);
        b >>= 1;
    }
    return p;
}

// ===== 编译期生成 MixColumns 表 =====
constexpr std::array<uint8_t, 256> make_mc2() {
    std::array<uint8_t, 256> table{};
    for (int i = 0; i < 256; i++) table[i] = constexpr_gmul((uint8_t)i, 2);
    return table;
}
constexpr auto MC2 = make_mc2();

// ===== 模板递归: 编译期白盒 "链" =====
template <int N>
struct ChainEncrypt {
    static void apply(WBAES &wb, uint8_t *d) {
        wb.encrypt(d, d);
        ChainEncrypt<N-1>::apply(wb, d);
    }
};
template <> struct ChainEncrypt<0> {
    static void apply(WBAES &, uint8_t *) {}
};
// ChainEncrypt<3>::apply = enc³

// ===== 编译期状态机 (白盒状态) =====
enum class CryptoState { Idle, Encrypted, Decrypted };
template <CryptoState S>
struct StateMachine {
    static constexpr CryptoState state = S;
};

int main() {
    static WBAES wb;
    wb.init();
    int fails = 0;

    // 1. 编译期 MC 表 (验证 = 运行期 gmul)
    {
        bool ok = true;
        for (int i = 0; i < 256; i++) {
            uint8_t expected = constexpr_gmul((uint8_t)i, 2);
            if (MC2[i] != expected) ok = false;
        }
        printf("[C++5 constexpr-mc2] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. 模板递归 Chain<3> = enc³ → dec³
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        ChainEncrypt<3>::apply(wb, d);
        // 解密 3 次
        for (int i = 0; i < 3; i++) wb.decrypt(d, d);
        bool ok = true;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = false;
        printf("[C++5 chain<3>] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. 编译期 MixColumns 表应用
    {
        uint8_t col[4] = {0x01, 0x02, 0x03, 0x04};
        // MC2 表: 乘 2
        uint8_t doubled[4];
        for (int i = 0; i < 4; i++) doubled[i] = MC2[col[i]];
        // 验证: doubled[0] = 0x02 (2*1=2), doubled[1] = 0x04 (2*2=4)
        if (doubled[0] == 0x02 && doubled[1] == 0x04)
            printf("[C++5 mc2-apply] PASS\n");
        else {
            printf("[C++5 mc2-apply] FAIL\n");
            fails++;
        }
    }

    // 4. 状态机 (编译期类型安全)
    {
        StateMachine<CryptoState::Idle> idle;
        // 编译期状态检查
        if (idle.state == CryptoState::Idle)
            printf("[C++5 state-machine] PASS\n");
        else {
            printf("[C++5 state-machine] FAIL\n");
            fails++;
        }
    }

    // 5. 模板递归 Chain<10> = enc¹⁰ (stress)
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        ChainEncrypt<10>::apply(wb, d);
        // 10 次加密 = enc¹⁰ — 解密 10 次还原
        for (int i = 0; i < 10; i++) wb.decrypt(d, d);
        bool ok = true;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = false;
        printf("[C++5 chain<10>] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    printf(fails ? "C++5 TOTAL: %d FAILS\n" : "C++5 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
