// wbaes_c_wrapper.h — 纯 C 接口 (供 ObjC/.m 使用)
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *wbaes_create(void);                                    // new WBAES + init
void wbaes_destroy(void *handle);
void wbaes_encrypt(void *handle, const uint8_t in[16], uint8_t out[16]);
void wbaes_decrypt(void *handle, const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif
