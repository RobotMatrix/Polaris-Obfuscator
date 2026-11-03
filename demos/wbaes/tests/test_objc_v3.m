// test_objc_v3.m — ObjC × JSON 策略文件开启 pass (无 __attribute__)
// 通过 C wrapper 调用白盒 — 白盒核心的 pass 由 JSON policy 控制
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <string.h>
#include "wbaes_c_wrapper.h"

@interface WBAESBoxV3 : NSObject
@property (assign, nonatomic) void *handle;
@end
@implementation WBAESBoxV3
- (instancetype)init {
    self = [super init];
    if (self) _handle = wbaes_create();
    return self;
}
- (void)dealloc { if (_handle) wbaes_destroy(_handle); }
- (NSData *)encryptData:(NSData *)data {
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_encrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
- (NSData *)decryptData:(NSData *)data {
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_decrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
@end

// Category (语法糖 — method 在白盒混淆的核心中调用)
@interface WBAESBoxV3 (HexExt)
- (NSString *)toHex:(NSData *)data;
- (NSData *)fromHex:(NSString *)hex;
@end
@implementation WBAESBoxV3 (HexExt)
- (NSString *)toHex:(NSData *)data {
    NSMutableString *s = [NSMutableString string];
    const uint8_t *b = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++)
        [s appendFormat:@"%02x", b[i]];
    return s;
}
- (NSData *)fromHex:(NSString *)hex {
    NSMutableData *d = [NSMutableData data];
    const char *p = hex.UTF8String;
    for (size_t i = 0; i + 1 < strlen(p); i += 2) {
        unsigned b; sscanf(p + i, "%2x", &b);
        [d appendBytes:&b length:1];
    }
    return d;
}
@end

// Protocol (语法糖)
@protocol CryptoProtocolV3
- (NSData *)encryptData:(NSData *)data;
@end

int main() {
    int fails = 0;
    @autoreleasepool {
        WBAESBoxV3 *box = [[WBAESBoxV3 alloc] init];

        // 1. 基础 roundtrip
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];
        NSData *ct = [box encryptData:ptData];
        NSData *rt = [box decryptData:ct];
        BOOL ok = memcmp(rt.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC3 basic] %s\n", ok ? "PASS" : "FAIL"); NSLog(@"[ObjC3] basic %@", ok ? @"PASS" : @"FAIL");

        // 2. Category hex
        NSString *hex = [box toHex:ct];
        NSData *fromHex = [box fromHex:hex];
        ok = memcmp(fromHex.bytes, ct.bytes, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC3 hex-category] %s\n", ok ? "PASS" : "FAIL");

        // 3. Protocol
        id<CryptoProtocolV3> proto = box;
        NSData *pct = [proto encryptData:ptData];
        ok = memcmp(pct.bytes, ct.bytes, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC3 protocol] %s\n", ok ? "PASS" : "FAIL");

        // 4. Block 捕获 + multi-block
        NSData *(^encBlock)(NSData *) = ^(NSData *d) { return [box encryptData:d]; };
        NSMutableArray<NSData *> *blocks = [NSMutableArray array];
        for (int i = 0; i < 4; i++) {
            uint8_t d[16];
            for (int j = 0; j < 16; j++) d[j] = (uint8_t)(i * 16 + j);
            [blocks addObject:[NSData dataWithBytes:d length:16]];
        }
        for (NSInteger i = 3; i >= 0; i--) blocks[i] = encBlock(blocks[i]);
        for (NSInteger i = 0; i < 4; i++) blocks[i] = [box decryptData:blocks[i]];
        ok = YES;
        for (int i = 0; i < 4; i++) {
            const uint8_t *b = blocks[i].bytes;
            for (int j = 0; j < 16; j++)
                if (b[j] != (uint8_t)(i * 16 + j)) ok = NO;
        }
        if (!ok) fails++;
        printf("[ObjC3 block-multi] %s\n", ok ? "PASS" : "FAIL");

        // 5. 泛型 ObjC 容器 (NSMapTable)
        NSMapTable<NSString *, NSData *> *mapTable =
            [NSMapTable strongToStrongObjectsMapTable];
        [mapTable setObject:ct forKey:@"key1"];
        NSData *mapped = [mapTable objectForKey:@"key1"];
        ok = memcmp(mapped.bytes, ct.bytes, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC3 map-table] %s\n", ok ? "PASS" : "FAIL");
    }

    NSLog(@"[WBAES-ObjC3] fails=%d %@", fails, fails == 0 ? @"ALL_PASS" : @"HAS_FAILS");
    printf(fails ? "ObjC3 TOTAL: %d FAILS\n" : "ObjC3 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
