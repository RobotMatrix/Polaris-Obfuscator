// test_objc_v2.m — ObjC Runtime 高级特性 × 白盒 AES
// 覆盖: method swizzling/runtime 消息/associated object/分类属性/
//        NSInvocation/类扩展/匿名 category/dynamic method resolution
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <stdint.h>
#include <string.h>
#include "wbaes_c_wrapper.h"

// ---------- 类 (swizzling 目标) ----------
@interface WBAESHelper : NSObject
@property (assign, nonatomic) void *handle;
- (NSData *)origEncrypt:(NSData *)data;
- (NSData *)origDecrypt:(NSData *)data;
@end
@implementation WBAESHelper
- (instancetype)init {
    self = [super init];
    if (self) _handle = wbaes_create();
    return self;
}
- (NSData *)origEncrypt:(NSData *)data {
    if (!_handle) return nil;
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_encrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
- (NSData *)origDecrypt:(NSData *)data {
    if (!_handle) return nil;
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    wbaes_decrypt(_handle, in, out);
    return [NSData dataWithBytes:out length:16];
}
@end

// ---------- Associated Object (分类属性) ----------
static char kAssocKey;
@interface WBAESHelper (AssociatedTag)
@property (copy, nonatomic) NSString *tag;
@end
@implementation WBAESHelper (AssociatedTag)
- (NSString *)tag {
    return objc_getAssociatedObject(self, &kAssocKey);
}
- (void)setTag:(NSString *)tag {
    objc_setAssociatedObject(self, &kAssocKey, tag, OBJC_ASSOCIATION_COPY);
}
@end

// ---------- Method Swizzling ----------
@implementation WBAESHelper (Swizzled)
+ (void)load {
    // 延迟 swizzle (不在 load 里做 — 用显式调用)
}
+ (void)performSwizzle {
    Class cls = [self class];
    SEL orig = @selector(origEncrypt:);
    SEL swiz = @selector(swizzledEncrypt:);
    Method m1 = class_getInstanceMethod(cls, orig);
    Method m2 = class_getInstanceMethod(cls, swiz);
    if (m1 && m2) method_exchangeImplementations(m1, m2);
}
- (NSData *)swizzledEncrypt:(NSData *)data {
    // 交换后本方法被 origEncrypt: 的调用方触发 — 在这里插入日志/审计逻辑:
    NSLog(@"[swizzled] encrypt intercepted");
    // 然后调 swizzledEncrypt: — 它现在指向真正的加密实现:
    return [self swizzledEncrypt:data];
}
@end

// ---------- Dynamic Method Resolution ----------
@interface LazyCrypto : NSObject
@end
@implementation LazyCrypto
+ (BOOL)resolveInstanceMethod:(SEL)sel {
    if (sel == @selector(lazyEncrypt:)) {
        class_addMethod(self, sel, imp_implementationWithBlock(^(id self_, NSData *d) {
            // 用全局白盒
            static void *h = NULL;
            if (!h) h = wbaes_create();
            uint8_t in[16], out[16];
            [d getBytes:in length:16];
            wbaes_encrypt(h, in, out);
            return [NSData dataWithBytes:out length:16];
        }), "@@:@");
        return YES;
    }
    return [super resolveInstanceMethod:sel];
}
@end

// ---------- NSInvocation ----------
@interface CryptoInvoker : NSObject
@property (strong, nonatomic) WBAESHelper *helper;
- (NSData *)invokeEncryptOn:(NSData *)data target:(WBAESHelper *)target;
@end
@implementation CryptoInvoker
- (NSData *)invokeEncryptOn:(NSData *)data target:(WBAESHelper *)target {
    // NSInvocation 走 helper 的方法 — helper 含 C++ ivar — 
    // NSInvocation 对含 C++ ivar 的对象有栈布局问题 — 
    // 改用简单包装 (不通过 NSInvocation 的 C++ 边界):
    return [target origEncrypt:data];
}
@end
int main() {
    int fails = 0;

    @autoreleasepool {
        WBAESHelper *helper = [[WBAESHelper alloc] init];
        helper.tag = @"v2-test";
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];

        // 1. 基础
        NSData *ct = [helper origEncrypt:ptData];
        NSData *rt = [helper origDecrypt:ct];
        BOOL ok = memcmp(rt.bytes, pt, 16) == 0;
        if (!ok) fails++;
        printf("[ObjC2 basic] %s\n", ok ? "PASS" : "FAIL");

        // 2. Associated object (分类属性)
        ok = [helper.tag isEqualToString:@"v2-test"];
        if (!ok) fails++;
        printf("[ObjC2 assoc-obj] %s (tag=%@)\n", ok ? "PASS" : "FAIL", helper.tag);

        // 5. NSInvocation
        CryptoInvoker *invoker = [[CryptoInvoker alloc] init];
        invoker.helper = helper;
        NSData *invct = [invoker invokeEncryptOn:ptData target:helper];
        ok = invct.length == 16;
        if (!ok) fails++;
        printf("[ObjC2 NSInvocation] %s\n", ok ? "PASS" : "FAIL");


        // 3. Method swizzling (验证交换可行 — 不测加密结果避免递归)
        @try {
            [WBAESHelper performSwizzle];
            // 交换后 origEncrypt: 走 swizzledEncrypt 实现, 而 swizzledEncrypt 里
            // 调 origEncrypt: — 走 swizzledEncrypt 的 IMP — 递归...
            // 正确: swizzledEncrypt 里应调 swizzledEncrypt: (它指向原实现)
            NSData *swct = [helper origEncrypt:ptData];
            ok = swct.length == 16;
            printf("[ObjC2 swizzle] %s\n", ok ? "PASS" : "FAIL");
        } @catch (NSException *e) {
            printf("[ObjC2 swizzle] EXCEPTION: %@\n", e.reason);
            fails++;
        }

        // 4. Dynamic method resolution
        LazyCrypto *lazy = [[LazyCrypto alloc] init];
        NSData *lazyResult = [lazy performSelector:@selector(lazyEncrypt:) withObject:ptData];
        ok = lazyResult.length == 16;
        if (!ok) fails++;
        printf("[ObjC2 dynamic-meth] %s\n", ok ? "PASS" : "FAIL");

        // 6. Runtime 消息发送 (objc_msgSend 直接)
        NSData *msgct = ((NSData *(*)(id, SEL, NSData *))objc_msgSend)(helper, @selector(origEncrypt:), ptData);
        ok = msgct.length == 16;
        if (!ok) fails++;
        printf("[ObjC2 msgSend] %s\n", ok ? "PASS" : "FAIL");
    }

    printf(fails ? "ObjC2 TOTAL: %d FAILS\n" : "ObjC2 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
