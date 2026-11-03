// devbind.h — 设备绑定因子 (纯客户端密钥分散, P2)
// 因子 = PRNG(Keychain半 ^ NSUD半 ^ UUID派生 ^ SEP签名[仅iOS]) → 32B
// 特性: 密钥成分不完整存在于二进制; 换设备因子不同 (表重建后密钥不同);
//       删 app 重装 Keychain 存活 (iOS) → 因子稳定, NSUD 丢失自动从 Keychain 重建.
#ifndef DEVBIND_H
#define DEVBIND_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int devbind_init(void);          // 0=ok (首次生成或读回), -1=失败
uint8_t devbind_byte(int i);     // 因子字节 i (0..31)
#ifdef __cplusplus
}
#endif
#endif
