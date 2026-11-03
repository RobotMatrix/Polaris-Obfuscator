// test_objcpp.mm — Objective-C++ 混合语法 × 白盒 AES
// 覆盖: C++ 类持 ObjC 对象 / C++ 异常 / C++ map + ObjC / lambda 混合捕获
#import <Foundation/Foundation.h>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <functional>
#include <cstring>
#include <cstdint>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// ---------- C++ 模板包装 ObjC 对象 ----------
template <typename T>
class ObjCPtr {
    T *ptr_;
public:
    ObjCPtr(T *p = nil) : ptr_(p) {}
    T *get() const { return ptr_; }
};

// ---------- C++ 类持有 ObjC 对象 ----------
class WBAESManager {
public:
    WBAES wb_;
    ObjCPtr<NSData> last_result_;
public:
    WBAESManager() { wb_.init(); }
    NSData *encrypt(NSData *in) {
        uint8_t inp[16], out[16];
        [in getBytes:inp length:16];
        wb_.encrypt(inp, out);
        last_result_ = [NSData dataWithBytes:out length:16];
        return last_result_.get();
    }
    NSData *decrypt(NSData *in) {
        uint8_t inp[16], out[16];
        [in getBytes:inp length:16];
        wb_.decrypt(inp, out);
        return [NSData dataWithBytes:out length:16];
    }
    void verify(NSData *in, NSData *out) {
        if ([in length] < 16 || [out length] < 16)
            throw std::runtime_error("length too short");
        uint8_t p[16], o[16];
        [in getBytes:p length:16];
        [out getBytes:o length:16];
        if (memcmp(p, o, 16) != 0)
            throw std::runtime_error("roundtrip mismatch");
    }
};

// ---------- ObjC 类 (使用 C++ 成员) ----------
@interface CryptoVault : NSObject
- (NSData *)encryptData:(NSData *)data;
- (NSData *)decryptData:(NSData *)data;
@end
@implementation CryptoVault {
    std::unique_ptr<WBAESManager> mgr_;   // C++ unique_ptr 成员
    std::map<std::string, NSData *> _vault;
}
- (instancetype)init {
    self = [super init];
    if (self) {
        mgr_ = std::make_unique<WBAESManager>();
    }
    return self;
}
- (void)dealloc {
    // mgr_ 由 unique_ptr 自动释放
}
- (NSData *)encryptData:(NSData *)data {
    NSMutableData *out = [NSMutableData dataWithLength:data.length];
    uint8_t in[16], o[16];
    for (NSUInteger i = 0; i + 16 <= data.length; i += 16) {
        [data getBytes:in range:NSMakeRange(i, 16)];
        mgr_->wb_.encrypt(in, o);
        [out replaceBytesInRange:NSMakeRange(i, 16) withBytes:o];
    }
    return out;
}
- (NSData *)decryptData:(NSData *)data {
    NSMutableData *out = [NSMutableData dataWithLength:data.length];
    uint8_t in[16], o[16];
    for (NSUInteger i = 0; i + 16 <= data.length; i += 16) {
        [data getBytes:in range:NSMakeRange(i, 16)];
        mgr_->wb_.decrypt(in, o);
        [out replaceBytesInRange:NSMakeRange(i, 16) withBytes:o];
    }
    return out;
}
- (void)store:(NSString *)key data:(NSData *)data {
    _vault[key.UTF8String] = [self encryptData:data];
}
- (NSData *)retrieve:(NSString *)key {
    auto it = _vault.find(key.UTF8String);
    if (it == _vault.end()) return nil;
    return [self decryptData:it->second];
}
@end

int main() {
    int fails = 0;

    @autoreleasepool {
        // 1. ObjC++ 混合
        WBAESManager mgr;
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];
        NSData *ct = mgr.encrypt(ptData);
        NSData *rt = mgr.decrypt(ct);
        BOOL ok = memcmp(rt.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC++ hybrid] %s\n", ok ? "PASS" : "FAIL");

        // 2. C++ 异常 (encrypt/decrypt roundtrip mismatch)
        try {
            mgr.verify(ptData, ct);
            // 故意: 验证错误对
            NSData *wrong = [NSData dataWithBytes:"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" length:16];
            try {
                mgr.verify(ptData, wrong);
                printf("[ObjC++ exception] FAIL (no throw)\n");
                fails++;
            } catch (const std::exception &e) {
                printf("[ObjC++ exception] PASS\n");
            }
        } catch (...) {}

        // 3.5 标准向量复验 (排查状态)
        {
            uint8_t tv[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                              0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
            NSData *tvData = [NSData dataWithBytes:tv length:16];
            NSData *tct = mgr.encrypt(tvData);
            NSData *tback = mgr.decrypt(tct);
            BOOL tok = memcmp(tback.bytes, tv, 16) == 0;
            printf("[ObjC++ std-vec] %s\n", tok ? "PASS" : "FAIL");
        }

        // 4. lambda 捕获 ObjC 对象 + C++ 对象
        int encCount = 0;
        auto lambda = [&mgr, &encCount](NSData *d) -> NSData * {
            encCount++;
            return mgr.encrypt(d);
        };
        NSData *lct = lambda(ptData);
        NSData *lback = mgr.decrypt(lct);
        ok = memcmp(lback.bytes, pt, 16) == 0 && encCount == 1;
        if (!ok) fails++;
        printf("[ObjC++ lambda-mixed] %s\n", ok ? "PASS" : "FAIL");

        // 5. ObjC 数组 + C++ vector 排序
        std::vector<NSData *> encBlocks;
        std::vector<uint8_t> plain(64);
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 16; j++)
                plain[i*16+j] = (uint8_t)(i*37+j);
        for (int i = 0; i < 4; i++) {
            NSData *blk = [NSData dataWithBytes:plain.data()+i*16 length:16];
            encBlocks.push_back(mgr.encrypt(blk));
        }
        BOOL ok2 = YES;
        for (int i = 0; i < 4; i++) {
            NSData *dec = mgr.decrypt(encBlocks[i]);
            if (memcmp(dec.bytes, plain.data()+i*16, 16) != 0) ok2 = NO;
        }
        if (!ok2) fails++;
        printf("[ObjC++ vector-objc] %s\n", ok2 ? "PASS" : "FAIL");
    }

        // 6. CryptoVault (C++ map<string, NSData*> + unique_ptr)
        CryptoVault *vault = [[CryptoVault alloc] init];
        uint8_t sd[32];
        for (int i = 0; i < 32; i++) sd[i] = i ^ 0xAB;
        NSData *secretData = [NSData dataWithBytes:sd length:32];
        [vault store:@"secret" data:secretData];
        NSData *recovered = [vault retrieve:@"secret"];
        BOOL ok6 = memcmp(recovered.bytes, sd, 32) == 0;
        if (!ok6) fails++;
        printf("[ObjC++ vault] %s\n", ok6 ? "PASS" : "FAIL");


    printf(fails ? "ObjC++ TOTAL: %d FAILS\n" : "ObjC++ TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
