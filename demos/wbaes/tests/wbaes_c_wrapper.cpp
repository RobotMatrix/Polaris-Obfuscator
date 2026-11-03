// wbaes_c_wrapper.cpp — C ABI wrapper (实现由 demo TU 提供)
// 注意: 这个 TU 依赖 demo_wbaes_noasm.cpp 中的 WBAES 完整定义
// 链接时必须同时链接 demo TU (否则符号未定义)

// WBAES 类声明 (链接时解析实现)
#include <cstdint>
class WBAES {
public:
    void init();
    void encrypt(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt(const uint8_t in[16], uint8_t out[16]) const;
};

extern "C" {
void *wbaes_create(void) {
    WBAES *wb = new WBAES();
    wb->init();
    return wb;
}
void wbaes_destroy(void *handle) { delete (WBAES *)handle; }
void wbaes_encrypt(void *handle, const uint8_t in[16], uint8_t out[16]) {
    ((WBAES *)handle)->encrypt(in, out);
}
void wbaes_decrypt(void *handle, const uint8_t in[16], uint8_t out[16]) {
    ((WBAES *)handle)->decrypt(in, out);
}
} // extern "C"
