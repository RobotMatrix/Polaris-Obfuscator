// devbind.mm — 设备绑定因子实现 (P2-1 + P2-2)
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "devbind.h"

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>   // iOS: UIDevice identifierForVendor
#endif

static uint8_t g_db[32];
static int g_ready = 0;

// ---- Keychain 半 (16B): kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly ----
static int kc_load(uint8_t out[16]) {
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                        (__bridge id)kSecAttrAccount: @"halfA",
                        (__bridge id)kSecReturnData: @YES};
    CFDataRef d = nullptr;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, (CFTypeRef *)&d);
    if (st == errSecSuccess && d) {
        NSData *nd = (__bridge_transfer NSData *)d;
        if (nd.length == 16) { memcpy(out, nd.bytes, 16); return 0; }
        return -1;
    }
    return -1;
}
static int kc_store(const uint8_t in[16]) {
    // 先删旧 (upsert)
    NSDictionary *del = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                          (__bridge id)kSecAttrAccount: @"halfA"};
    SecItemDelete((__bridge CFDictionaryRef)del);
    NSData *data = [NSData dataWithBytes:in length:16];
    NSDictionary *add = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                          (__bridge id)kSecAttrAccount: @"halfA",
                          (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                          (__bridge id)kSecValueData: data};
    return SecItemAdd((__bridge CFDictionaryRef)add, nullptr) == errSecSuccess ? 0 : -1;
}

// ---- NSUserDefaults 半 (16B): 混进无关配置项 (伪装 metric) ----
static NSString * const kUDKey = @"last_metric_ts_seq";
static int ud_load(uint8_t out[16]) {
    NSString *s = [[NSUserDefaults standardUserDefaults] stringForKey:kUDKey];
    if (!s || s.length != 32) return -1;
    for (int i = 0; i < 16; i++) {
        unsigned v;
        if (![[NSScanner scannerWithString:[s substringWithRange:NSMakeRange(i*2, 2)]] scanHexInt:&v]) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}
static void ud_store(const uint8_t in[16]) {
    NSMutableString *s = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < 16; i++) [s appendFormat:@"%02x", in[i]];
    [[NSUserDefaults standardUserDefaults] setObject:s forKey:kUDKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

// ---- UUID 派生 16B (设备指纹, 静态可变但难仿造) ----
static void uuid_derive(uint8_t out[16]) {
    NSString *uid = nil;
#if TARGET_OS_IPHONE
    uid = [[UIDevice currentDevice].identifierForVendor UUIDString];
#else
    char hn[128] = {0};
    gethostname(hn, sizeof(hn) - 1);
    uid = [NSString stringWithUTF8String:hn];
    if (!uid || !uid.length) uid = @"mac-unknown";
#endif
    if (!uid || !uid.length) uid = @"fallback-uid";
    NSData *d = [uid dataUsingEncoding:NSUTF8StringEncoding];
    // FNV-1a 64 双轮 → 16B
    uint64_t h1 = 0xcbf29ce484222325ULL, h2 = 0x9e3779b97f4a7c15ULL;
    const uint8_t *p = (const uint8_t *)d.bytes;
    for (NSUInteger i = 0; i < d.length; i++) {
        h1 = (h1 ^ p[i]) * 0x100000001b3ULL;
        h2 = (h2 ^ p[d.length - 1 - i]) * 0x100000001b3ULL;
    }
    memcpy(out, &h1, 8);
    memcpy(out + 8, &h2, 8);
}

// ---- iOS SEP 增强: SecKey 随机签名 → SHA256 前 16B (失败静默跳过) ----
#if TARGET_OS_IPHONE
static int sep_derive(uint8_t out[16]) {
    NSData *tag = [@"com.bangcle.wbaes.sepk" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *gen = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                          (__bridge id)kSecAttrKeySizeInBits: @256,
                          (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                          (__bridge id)kSecPrivateKeyAttrs:
                              @{(__bridge id)kSecAttrIsPermanent: @YES,
                                (__bridge id)kSecAttrApplicationTag: tag}};
    SecKeyRef pk = nullptr;
    // 已存在则复用
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassKey,
                        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                        (__bridge id)kSecAttrApplicationTag: tag,
                        (__bridge id)kSecReturnRef: @YES};
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, (CFTypeRef *)&pk) != errSecSuccess) {
        if (SecKeyGeneratePair((__bridge CFDictionaryRef)gen, &pk, nullptr) != errSecSuccess || !pk)
            return -1;
    }
    uint8_t challenge[16];
    int rc = SecRandomCopyBytes(kSecRandomDefault, 16, challenge);
    if (rc != errSecSuccess) { if (pk) CFRelease(pk); return -1; }
    NSData *cd = [NSData dataWithBytes:challenge length:16];
    CFErrorRef err = nullptr;
    NSData *sig = (__bridge_transfer NSData *)SecKeyCreateSignature(
        pk, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)cd, &err);
    if (pk) CFRelease(pk);
    if (!sig || sig.length < 16) return -1;
    memcpy(out, sig.bytes, 16);   // 签名前 16B (含随机数, 每次不同 → 需缓存!)
    return 0;
}
#endif

// SEP 签名结果持久化 (签名含随机数, 每次不同 → 必须缓存, 否则因子漂移)
static int kc_load_acct(const char *acct, uint8_t out[16]) {
    NSString *acc = [NSString stringWithUTF8String:acct];
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                        (__bridge id)kSecAttrAccount: acc,
                        (__bridge id)kSecReturnData: @YES};
    CFDataRef d = nullptr;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, (CFTypeRef *)&d) == errSecSuccess && d) {
        NSData *nd = (__bridge_transfer NSData *)d;
        if (nd.length == 16) { memcpy(out, nd.bytes, 16); return 0; }
    }
    return -1;
}
static int kc_store_acct(const char *acct, const uint8_t in[16]) {
    NSString *acc = [NSString stringWithUTF8String:acct];
    NSDictionary *del = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                          (__bridge id)kSecAttrAccount: acc};
    SecItemDelete((__bridge CFDictionaryRef)del);
    NSData *data = [NSData dataWithBytes:in length:16];
    NSDictionary *add = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"com.bangcle.wbaes.devbind",
                          (__bridge id)kSecAttrAccount: acc,
                          (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                          (__bridge id)kSecValueData: data};
    return SecItemAdd((__bridge CFDictionaryRef)add, nullptr) == errSecSuccess ? 0 : -1;
}

extern "C" int devbind_init(void) {
    if (g_ready) return 0;
    uint8_t ha[16] = {0}, hb[16] = {0}, uu[16] = {0};
    // Keychain 半: 读回 or 生成
    if (kc_load(ha) != 0) {
        SecRandomCopyBytes(kSecRandomDefault, 16, ha);
        kc_store(ha);
    }
    // NSUD 半: 读回 or 生成 (与 Keychain 无关独立)
    if (ud_load(hb) != 0) {
        SecRandomCopyBytes(kSecRandomDefault, 16, hb);
        ud_store(hb);
    }
    // UUID 派生
    uuid_derive(uu);
    // SEP 增强 (iOS): 首次签名 → 存 Keychain; 后续读回 (保证因子跨会话稳定)
    uint8_t sep[16] = {0};
#if TARGET_OS_IPHONE
    if (kc_load_acct("halfS", sep) != 0) {
        if (sep_derive(sep) == 0) {
            kc_store_acct("halfS", sep);   // 缓存 (失败则每次 init 重算, 因子漂移但不崩)
        }
    }
#endif
    // 32B 因子 = FNV 双域混合 (半A⊕半B⊕UUID⊕SEP 挤压到 32B)
    for (int i = 0; i < 16; i++) {
        g_db[i]    = ha[i] ^ hb[i] ^ uu[i] ^ sep[i];
        g_db[16+i] = hb[i] ^ uu[i] ^ ha[(i+5)&15] ^ sep[(i+3)&15];
    }
    g_ready = 1;
    return 0;
}

extern "C" uint8_t devbind_byte(int i) {
    if (!g_ready) devbind_init();
    return g_db[i & 31];
}
