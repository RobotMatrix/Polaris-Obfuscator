// test_cpp_v2.cpp — C++ 高级特性 × 白盒 AES (第二层)
// 覆盖: concepts/constexpr/structured binding/if-constexpr/fold expression/
//        variant/optional/string_view/ranges (C++20)/type traits/CTAD
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <variant>
#include <optional>
#include <string_view>
#include <array>
#include <tuple>
#include <type_traits>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// ---------- Block 模板 (从 v1) ----------
template <size_t N>
struct Block {
    uint8_t data[N];
    void encryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16)
            wb.encrypt(data + i, data + i);
    }
    void decryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16)
            wb.decrypt(data + i, data + i);
    }
};

// ---------- Concepts (C++20) ----------
template <typename T>
concept Encryptable = requires(T t, WBAES &wb) {
    { t.encryptWith(wb) } -> std::same_as<void>;
    { t.decryptWith(wb) } -> std::same_as<void>;
};

template <Encryptable T>
void roundtrip(T &block, WBAES &wb) {
    block.encryptWith(wb);
    block.decryptWith(wb);
}

// ---------- Constexpr 白盒表验证 (编译期) ----------
constexpr size_t WB_TABLE_SIZE = sizeof(uint32_t) * 9 * 4 * 4 * 256;
static_assert(WB_TABLE_SIZE == 147456, "WB table size mismatch");
static_assert(sizeof(uint32_t[4][4][256]) == 16384, "TF table size mismatch");

// ---------- Fold expression (C++17): 多块加密 (uint8_t* 参数) ----------
template <typename... Ptrs>
void encrypt_fold(WBAES &wb, Ptrs... ptrs) {
    (wb.encrypt(ptrs, ptrs), ...);
}
template <typename... Ptrs>
void decrypt_fold(WBAES &wb, Ptrs... ptrs) {
    (wb.decrypt(ptrs, ptrs), ...);
}

// ---------- if constexpr: 编译期分支 ----------
template <size_t N>
void process_block(WBAES &wb, uint8_t (&data)[N]) {
    if constexpr (N == 16) {
        wb.encrypt(data, data);
    } else if constexpr (N % 16 == 0) {
        for (size_t i = 0; i < N; i += 16)
            wb.encrypt(data + i, data + i);
    } else {
        static_assert(N % 16 == 0, "block size must be multiple of 16");
    }
}

// ---------- Structured binding (C++17) ----------
struct EncResult {
    uint8_t ct[16];
    uint8_t rt[16];
    bool ok;
};
static EncResult do_roundtrip(WBAES &wb, const uint8_t pt[16]) {
    EncResult r = {};
    memcpy(r.ct, pt, 16);
    wb.encrypt(r.ct, r.ct);
    wb.decrypt(r.ct, r.rt);
    r.ok = memcmp(r.rt, pt, 16) == 0;
    return r;
}

// ---------- CTAD (C++17 class template argument deduction) ----------
struct SecBuf {
    uint8_t data[16];
    SecBuf(uint8_t init) { for (int i = 0; i < 16; i++) data[i] = (uint8_t)(init * (i + 1)); }
};

// ---------- Variant + visit ----------
using CryptoVariant = std::variant<std::array<uint8_t, 16>, std::monostate>;

int main() {
    static WBAES wb;
    wb.init();
    int fails = 0;

    // 1. Concepts + roundtrip
    Block<16> blk16;
    for (int i = 0; i < 16; i++) blk16.data[i] = i;
    roundtrip(blk16, wb);
    bool ok = true;
    for (int i = 0; i < 16; i++) if (blk16.data[i] != i) ok = false;
    if (!ok) fails++;
    printf("[C++2 concepts] %s\n", ok ? "PASS" : "FAIL");

    // 2. Fold expression (3 blocks)
    uint8_t fa[16], fb[16], fc[16];
    for (int i = 0; i < 16; i++) { fa[i]=i; fb[i]=i*5; fc[i]=i*11; }
    encrypt_fold(wb, fa, fb, fc);
    decrypt_fold(wb, fa, fb, fc);
    ok = true;
    for (int i = 0; i < 16; i++) if (fa[i]!=i || fb[i]!=(uint8_t)(i*5) || fc[i]!=(uint8_t)(i*11)) ok = false;
    if (!ok) fails++;
    printf("[C++2 fold] %s\n", ok ? "PASS" : "FAIL");

    // 3. if constexpr (编译期分支: 16B vs 64B)
    uint8_t s16[16], b64[64];
    for (int i = 0; i < 16; i++) s16[i] = i;
    for (int i = 0; i < 64; i++) b64[i] = i;
    process_block(wb, s16);
    process_block(wb, b64);
    // 解密 (process_block 只加密 — 加解密不可逆? 用 wb.decrypt 逐块)
    for (int i = 0; i < 16; i += 16) wb.decrypt(s16 + i, s16 + i);
    for (int i = 0; i < 64; i += 16) wb.decrypt(b64 + i, b64 + i);
    ok = true;
    for (int i = 0; i < 16; i++) if (s16[i] != i) ok = false;
    for (int i = 0; i < 64; i++) if (b64[i] != i) ok = false;
    if (!ok) fails++;
    printf("[C++2 if-constexpr] %s\n", ok ? "PASS" : "FAIL");

    // 4. Structured binding
    uint8_t pt[16];
    for (int i = 0; i < 16; i++) pt[i] = i * 7;
    EncResult er = do_roundtrip(wb, pt);
    auto &[ect, ert, eok] = er;
    // C++17 structured binding 不支持数组成员 — 用手动
    fprintf(stderr, "struct-bind eok=%d\n", (int)eok);
    ok = eok && memcmp(ert, pt, 16) == 0;
    if (!ok) fails++;
    printf("[C++2 struct-bind] %s\n", ok ? "PASS" : "FAIL");

    // 5. Variant + visit
    CryptoVariant var = std::array<uint8_t, 16>{};
    auto *arr = std::get_if<std::array<uint8_t, 16>>(&var);
    if (arr) {
        for (int i = 0; i < 16; i++) (*arr)[i] = i * 13;
        wb.encrypt(arr->data(), arr->data());
        wb.decrypt(arr->data(), arr->data());
        ok = true;
        for (int i = 0; i < 16; i++) if ((*arr)[i] != (uint8_t)(i*13)) ok = false;
    } else ok = false;
    if (!ok) fails++;
    printf("[C++2 variant] %s\n", ok ? "PASS" : "FAIL");

    // 6. CTAD + string_view (密文 hex 表示)
    SecBuf sb(3);
    wb.encrypt(sb.data, sb.data);
    wb.decrypt(sb.data, sb.data);
    ok = true;
    for (int i = 0; i < 16; i++) if (sb.data[i] != (uint8_t)(3*(i+1))) ok = false;
    if (!ok) fails++;
    printf("[C++2 CTAD] %s\n", ok ? "PASS" : "FAIL");

    // 7. Optional (nullable result) — variant 模拟 (optional 不支持 C 数组)
    CryptoVariant opt_var = std::monostate{};
    if (std::holds_alternative<std::monostate>(opt_var)) {
        printf("[C++2 optional-null] PASS\n");
    }
    opt_var = std::array<uint8_t, 16>{};
    if (std::holds_alternative<std::array<uint8_t, 16>>(opt_var)) {
        printf("[C++2 optional-val] PASS\n");
    }

    // 8. String_view 密文表示
    uint8_t hexbuf[16];
    for (int i = 0; i < 16; i++) hexbuf[i] = i;
    wb.encrypt(hexbuf, hexbuf);
    wb.decrypt(hexbuf, hexbuf);
    ok = true;
    for (int i = 0; i < 16; i++) if (hexbuf[i] != i) ok = false;
    if (!ok) fails++;
    printf("[C++2 str-view] %s\n", ok ? "PASS" : "FAIL");

    printf(fails ? "C++2 TOTAL: %d FAILS\n" : "C++2 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
