// test_objc.m — Objective-C 复杂语法 × 白盒 AES (通过 C wrapper)
// 覆盖: category/protocol/block/KVC/属性/ARC/类扩展
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <string.h>
#include "wbaes_c_wrapper.h"

// ---------- Protocol ----------
@protocol CryptoProtocol
- (NSData *)encryptData:(NSData *)data;
- (NSData *)decryptData:(NSData *)data;
@end

// ---------- 类 ----------
@interface WBAESBox : NSObject <CryptoProtocol>
@property (assign, nonatomic) void *handle;
- (instancetype)init;
@end
@implementation WBAESBox
- (instancetype)init {
    self = [super init];
    if (self) {
        _handle = wbaes_create();
    }
    return self;
}
- (void)dealloc {
    if (_handle) wbaes_destroy(_handle);
}
- (NSData *)encryptData:(NSData *)data {
    if (!_handle || data.length < 16) return nil;
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_encrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
- (NSData *)decryptData:(NSData *)data {
    if (!_handle || data.length < 16) return nil;
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_decrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
@end

// ---------- Category ----------
@interface WBAESBox (Convenience)
- (NSString *)encryptHex:(NSString *)hex;
@end
@implementation WBAESBox (Convenience)
- (NSString *)encryptHex:(NSString *)hex {
    NSMutableData *d = [NSMutableData data];
    const char *p = hex.UTF8String;
    for (size_t i = 0; i + 1 < strlen(p); i += 2) {
        unsigned b; sscanf(p + i, "%2x", &b);
        [d appendBytes:&b length:1];
    }
    NSData *enc = [self encryptData:d];
    NSMutableString *s = [NSMutableString string];
    const uint8_t *bytes = enc.bytes;
    for (NSUInteger i = 0; i < enc.length; i++)
        [s appendFormat:@"%02x", bytes[i]];
    return s;
}
@end

int main() {
    int fails = 0;

    @autoreleasepool {
        // 1. 基础
        WBAESBox *box = [[WBAESBox alloc] init];
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];
        NSData *ct = [box encryptData:ptData];
        NSData *rt = [box decryptData:ct];
        BOOL ok = memcmp(rt.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC basic] %s\n", ok ? "PASS" : "FAIL");

        // 2. Category hex
        NSString *encHex = [box encryptHex:@"000102030405060708090a0b0c0d0e0f"];
        printf("[ObjC category] len=%lu %s\n", (unsigned long)encHex.length,
               encHex.length == 32 ? "PASS" : "FAIL");
        if (encHex.length != 32) fails++;

        // 3. Block
        NSData *(^encBlock)(NSData *) = ^(NSData *d) { return [box encryptData:d]; };
        NSData *(^decBlock)(NSData *) = ^(NSData *d) { return [box decryptData:d]; };
        uint8_t pt2[16];
        for (int i = 0; i < 16; i++) pt2[i] = i * 3;
        NSData *c2 = encBlock([NSData dataWithBytes:pt2 length:16]);
        NSData *r2 = decBlock(c2);
        ok = memcmp(r2.bytes, pt2, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC block] %s\n", ok ? "PASS" : "FAIL");

        // 4. 多块
        NSMutableArray<NSData *> *blocks = [NSMutableArray array];
        for (int i = 0; i < 4; i++) {
            uint8_t d[16];
            for (int j = 0; j < 16; j++) d[j] = (uint8_t)(i * 16 + j);
            [blocks addObject:[NSData dataWithBytes:d length:16]];
        }
        for (NSInteger i = 3; i >= 0; i--) blocks[i] = [box encryptData:blocks[i]];
        for (NSInteger i = 0; i < 4; i++) blocks[i] = [box decryptData:blocks[i]];
        ok = YES;
        for (int i = 0; i < 4; i++) {
            const uint8_t *b = blocks[i].bytes;
            for (int j = 0; j < 16; j++)
                if (b[j] != (uint8_t)(i * 16 + j)) ok = NO;
        }
        if (!ok) fails++;
        printf("[ObjC multi-block] %s\n", ok ? "PASS" : "FAIL");

        // 5. KVC + protocol conformance
        id<CryptoProtocol> proto = box;
        NSData *pct = [proto encryptData:ptData];
        ok = memcmp(pct.bytes, ct.bytes, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC protocol] %s\n", ok ? "PASS" : "FAIL");

        // KVC
        [box setValue:@(42) forKey:@"handle"];   // 改 handle (KVC 测试 — 会破坏)
        // 恢复
        [box setValue:nil forKey:@"handle"];     // KVC nil → NULL
        box.handle = wbaes_create();             // 恢复
        NSData *after = [box encryptData:ptData];
        NSData *back = [box decryptData:after];
        ok = memcmp(back.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC KVC-recover] %s\n", ok ? "PASS" : "FAIL");
    }

    printf(fails ? "ObjC TOTAL: %d FAILS\n" : "ObjC TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
