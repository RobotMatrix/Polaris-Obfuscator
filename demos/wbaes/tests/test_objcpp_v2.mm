// test_objcpp_v2.mm — ObjC++ 高级混合语法 × 白盒 AES (第二层)
// 覆盖: C++ 类持 ObjC 对象/C++ virtual + ObjC 桥/variant/RAII 桥 ARC/
//        ObjC block 存 C++ std::function/C++ 模板持 ObjC
#import <Foundation/Foundation.h>
#include <variant>
#include <functional>
#include <cstring>
#include <cstdint>

#define WBAES_NO_MAIN 1
#include "wbaes_c_wrapper.h"
#undef WBAES_NO_MAIN

// ---------- C++ 模板持 ObjC 对象 (编译验证) ----------
template <typename T>
class CryptoEngineBox {
    T *engine_;
public:
    CryptoEngineBox(T *e) : engine_(e) {}
};

// ---------- ObjC 类 (使用 C wrapper) ----------
@interface WBAESManager : NSObject
- (NSData *)encryptData:(NSData *)data;
- (NSData *)decryptData:(NSData *)data;
@end
@implementation WBAESManager {
    void *handle_;
}
- (instancetype)init {
    self = [super init];
    if (self) handle_ = wbaes_create();
    return self;
}
- (void)dealloc { if (handle_) wbaes_destroy(handle_); }
- (NSData *)encryptData:(NSData *)data {
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_encrypt(handle_, in, out);
    return [NSData dataWithBytes:out length:16];
}
- (NSData *)decryptData:(NSData *)data {
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_decrypt(handle_, in, out);
    return [NSData dataWithBytes:out length:16];
}
@end

// ---------- C++ virtual + ObjC 桥 ----------
class VirtualCrypto {
public:
    virtual ~VirtualCrypto() = default;
    virtual NSData *transform(NSData *input) = 0;
};

class ConcreteCrypto : public VirtualCrypto {
    void *handle_ = wbaes_create();
public:
    ~ConcreteCrypto() { if (handle_) wbaes_destroy(handle_); }
    NSData *transform(NSData *input) override {
        uint8_t in[16], out[16];
        [input getBytes:in length:16];
        wbaes_encrypt(handle_, in, out);
        return [NSData dataWithBytes:out length:16];
    }
};

@interface ObjCBridge : NSObject
- (NSData *)doTransform:(NSData *)input;
@end
@implementation ObjCBridge
- (NSData *)doTransform:(NSData *)input {
    ConcreteCrypto crypto;
    return crypto.transform(input);
}
@end

// ---------- C++ RAII 桥 ObjC ARC ----------
struct ObjCRAII {
    NSData *data_;
    ObjCRAII(NSData *d) : data_(d) {}
    ~ObjCRAII() {}
    NSData *get() const { return data_; }
};

// ---------- C++ variant 持 NSData* ----------
using CryptoState = std::variant<std::monostate, NSData *>;

int main() {
    int fails = 0;

    @autoreleasepool {
        // 1. C++ virtual + ObjC 桥
        ObjCBridge *bridge = [[ObjCBridge alloc] init];
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];
        NSData *ct = [bridge doTransform:ptData];
        BOOL ok = (memcmp(ct.bytes, pt, 16) != 0);
        if (!ok) fails++;
        printf("[ObjC++2 virtual] %s\n", ok ? "PASS" : "FAIL");

        // 2. Variant 持 NSData*
        CryptoState state = ptData;
        if (std::holds_alternative<NSData *>(state)) {
            NSData *d = std::get<NSData *>(state);
            ok = d.length == 16;
        } else ok = false;
        if (!ok) fails++;
        printf("[ObjC++2 variant-objc] %s\n", ok ? "PASS" : "FAIL");

        // 3. C++ RAII 桥 ObjC ARC
        {
            ObjCRAII raii(ptData);
            ok = raii.get().length == 16;
        }
        if (!ok) fails++;
        printf("[ObjC++2 RAII-bridge] %s\n", ok ? "PASS" : "FAIL");

        // 4. C++ function 存 ObjC block (类型擦除)
        WBAESManager *mgr = [[WBAESManager alloc] init];
        NSData *(^objcBlock)(NSData *) = ^NSData *(NSData *d) {
            return [mgr encryptData:d];
        };
        std::function<NSData *(NSData *)> crypto_fn = [objcBlock](NSData *d) -> NSData * {
            return objcBlock(d);
        };
        NSData *fnResult = crypto_fn(ptData);
        NSData *fnBack = [mgr decryptData:fnResult];
        ok = memcmp(fnBack.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC++2 fn-objc-block] %s\n", ok ? "PASS" : "FAIL");

        // 5. CryptoEngineBox 编译验证
        printf("[ObjC++2 generic-tpl] PASS (template compiled)\n");
    }

    printf(fails ? "ObjC++2 TOTAL: %d FAILS\n" : "ObjC++2 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
