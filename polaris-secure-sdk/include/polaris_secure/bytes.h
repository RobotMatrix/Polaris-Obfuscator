// polaris_secure/bytes.h — 字节视图 / 安全缓冲区 / 十六进制工具
// 参考架构《跨平台App安全保护架构研究》§7 密码服务层基础类型。
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace polaris_secure {

// 只读字节视图: 密码 API 统一入参, 不持有内存。
struct ByteView {
    const uint8_t* data = nullptr;
    size_t size = 0;

    ByteView() = default;
    ByteView(const uint8_t* d, size_t n) : data(d), size(n) {}
    ByteView(const char* s, size_t n)
        : data(reinterpret_cast<const uint8_t*>(s)), size(n) {}
    ByteView(const std::vector<uint8_t>& v) : data(v.data()), size(v.size()) {}
    ByteView(const std::string& s)
        : data(reinterpret_cast<const uint8_t*>(s.data())), size(s.size()) {}

    bool empty() const { return size == 0; }
    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
};

// 安全缓冲区: 析构 / clear 时清零内存, 减少密钥明文残留 (§6.2 缩小明文暴露窗口)。
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t n, uint8_t fill = 0) : buf_(n, fill) {}
    SecureBuffer(const uint8_t* d, size_t n) : buf_(d, d + n) {}

    SecureBuffer(const SecureBuffer& o) : buf_(o.buf_) {}
    SecureBuffer& operator=(const SecureBuffer& o) {
        if (this != &o) buf_ = o.buf_;
        return *this;
    }
    SecureBuffer(SecureBuffer&& o) noexcept : buf_(std::move(o.buf_)) { o.buf_.clear(); }
    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            clear();
            buf_ = std::move(o.buf_);
            o.buf_.clear();
        }
        return *this;
    }
    ~SecureBuffer() { clear(); }

    void clear() {
        if (!buf_.empty()) {
            volatile uint8_t* p = buf_.data();
            for (size_t i = 0; i < buf_.size(); ++i) p[i] = 0;
        }
        buf_.clear();
    }

    uint8_t* data() { return buf_.data(); }
    const uint8_t* data() const { return buf_.data(); }
    size_t size() const { return buf_.size(); }
    bool empty() const { return buf_.empty(); }
    void resize(size_t n) { buf_.resize(n); }
    void assign(const uint8_t* d, size_t n) {
        clear();
        buf_.assign(d, d + n);
    }
    uint8_t& operator[](size_t i) { return buf_[i]; }
    const uint8_t& operator[](size_t i) const { return buf_[i]; }
    std::vector<uint8_t> copyToVector() const { return buf_; }

    bool operator==(const SecureBuffer& o) const { return buf_ == o.buf_; }

private:
    std::vector<uint8_t> buf_;
};

// ---- 十六进制工具 ----
inline std::string to_hex(const uint8_t* d, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[d[i] >> 4]);
        s.push_back(kHex[d[i] & 15]);
    }
    return s;
}
inline std::string to_hex(ByteView v) { return to_hex(v.data, v.size); }

// 解析十六进制; 失败返回 false。
inline bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = -1, lo = -1;
        char a = s[i], b = s[i + 1];
        for (int k = 0; k < 16; ++k) {
            if (a == "0123456789abcdef"[k] || a == "0123456789ABCDEF"[k]) hi = k;
            if (b == "0123456789abcdef"[k] || b == "0123456789ABCDEF"[k]) lo = k;
        }
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// 恒定时间字节比较 (防时序侧信道泄露 MAC/签名比较结果)。
inline bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= static_cast<uint8_t>(a[i] ^ b[i]);
    return d == 0;
}

}  // namespace polaris_secure
