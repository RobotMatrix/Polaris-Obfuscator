# WBAES 最终导出 — 最强混淆配置 (10-pass)

**导出日期**: 2026-11-03
**密钥**: 见 `key/` (编译期烧入白盒表, 换钥须重编)
**混淆**: Polaris clang (LLVM 16 fork) — 10 pass 全开

## 一、AES-128 密钥

```
d796fc6e49595e5f366a5e55744431be
```

- **唯一密钥源**: `key/wbaes_key.h` (4×64B 随机块分片, KBLK⊕CBLK @ KOFF/COFF)
- **验证**: `python3 key/verify_key.py key/wbaes_key.h` → MATCH: True
- **标准库互操作** (与白盒实现加解密互通):

```bash
# 加密 (ECB, 单块 16B, PKCS7 去 nopad 按需)
openssl enc -aes-128-ecb -K d796fc6e49595e5f366a5e55744431be -nopad -in pt.bin -out ct.bin
# 解密
openssl enc -d -aes-128-ecb -K d796fc6e49595e5f366a5e55744431be -nopad -in ct.bin -out pt.bin
```

- **测试向量** (PCBC/CTR 等其他模式白盒未实现, 仅 ECB):
  - pt: `6bc1bee22e409f96e93d7e117393172a`
  - ct: `de23992aa3c7427f3ad40fda83730d07`

⚠️ 白盒表由该密钥编译期生成 — 密钥与二进制绑定, 换钥必须重新编译 (`wbaes_key.h` 为唯一入口)。

## 二、混淆配置 (10 pass, 按序)

```
alias,gvenc,indcall,indbr,mba,sub,bcf,fla,ccc,merge
```

| Pass | 防护维度 |
|---|---|
| alias | 数据访问别名指针链 — 数据流断链 |
| gvenc | 全局表运行时解密 — 静态 dump 失效 |
| indcall | 直接调用→函数指针 — callgraph 断链 |
| indbr | 直接跳转→跳转表 — CFG 恢复破坏 |
| mba | 算术 MBA 恒等替换 — 反编译器优化失效 |
| sub | 指令级替换 |
| bcf | 垃圾块+不透明谓词 — 符号执行路径爆炸 |
| fla | 控制流打平 — IDA F5 出 state machine |
| ccc | 自定义调用约定 |
| merge | 函数合并 |

顺序敏感: `alias` 首位, `fla` 末位 (打平须在控制流变换后)。

## 三、产物清单

### macOS (arm64, 可直接运行)

| 文件 | 内容 | SHA256 (前16) |
|---|---|---|
| `macos/wbaes_c_v6_test` | C v6 多文件项目测试 (5/5) | aa5aca27c3a9316a |
| `macos/wbaes_cpp_v6_test` | C++ v6 STL/并发测试 (6/6) | 85bfdfae9fee24cb |
| `macos/wbaes_c_v7_test` | C v7 深层结构测试 (5/5) | c6c502d443732fef |

### iOS 真机 (iPhone 13, arm64)

| 文件 | 状态 | 内容 |
|---|---|---|
| `ios-device/c6ui_test-signed.ipa` | ✅ 已签名已装机验证 | C v6 UI 版 (8-pass, 2026-11-03 上午) |
| `ios-device/cpp6ui_test-signed.ipa` | ✅ 已签名已装机验证 | C++ v6 UI 版 (8-pass) |
| `ios-device/c7ui_test-signed.ipa` | ✅ 已签名已装机验证 | C v7 UI 版 (8-pass) |
| `ios-device/c6_test-signed.ipa` 等 | console 版 (已装机验证) | 首轮 console 测试 |
| `ios-device/unsigned-binaries/c6ui_ios` | 10-pass 重编 **未签名** | 见「签名证书」说明 |

### 静态库 (10-pass 混淆, 供集成)

| 文件 | 平台 | 链接方式 |
|---|---|---|
| `ios-libs/libwbaes_ios_arm64.a` | iOS arm64 | C++: `WBAES::init/encrypt/decrypt` |
| `ios-libs/libwbaes_cwrap_ios_arm64.a` | iOS arm64 | C ABI: `wbaes_create/encrypt/decrypt/destroy` |
| `macos-libs/libwbaes_macos_arm64.a` | macOS arm64 | 同上 (C++ 接口) |
| `macos-libs/libwbaes_cwrap_macos_arm64.a` | macOS arm64 | 同上 (C ABI) |

集成示例 (C ABI):
```c
#include "wbaes_c_wrapper.h"
void *h = wbaes_create();
wbaes_encrypt(h, in16, out16);
wbaes_decrypt(h, in16, out16);
wbaes_destroy(h);
```
链接: `libwbaes_cwrap_*.a + libwbaes_*_*.a -lc++` (两个都要)。

### 源码 (`src/`, 可完整复现)

- `wbaes_key.h` — 密钥 (唯一源)
- `demo_wbaes_noasm.cpp` — 白盒核心 (无注解, JSON policy 驱动)
- `demo_wbaes.cpp` — 注解版
- `tiny_aes.c` — 标准 AES 参照实现
- `test_c_v6.c` / `test_cpp_v6.cpp` / `test_c_v7.c` — console 测试
- `test_c6_ui.mm` / `test_cpp6_ui.mm` / `test_c7_ui.mm` — iOS UI 测试
- `c_project/` — C v6 四模块 (哈希表/CRC32/Base64/大整数)
- `wbaes_c_wrapper.h/.cpp` — C ABI
- `policy_allpass.json` — pass 策略 (8-pass 版; 10-pass 直接命令行传)

## 四、复现构建

```bash
CL=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/src/build/bin/clang++
P=alias,gvenc,indcall,indbr,mba,sub,bcf,fla,ccc,merge

# macOS 单文件测试:
$CL -O2 -std=c++17 -I. tests/test_c_v7.c tiny_aes.c -mllvm -passes=$P -o out

# iOS 二进制 (两段式, Polaris clang 链 iOS framework 有 bug):
$CL -arch arm64 -isysroot <iOS_SDK> -mios-version-min=16.0 -O2 -std=c++17 -I. \
    -x objective-c++ tests/test_c7_ui.mm -mllvm -passes=$P -c -o c7ui.o
LD=$(xcrun -sdk iphoneos -f ld)
$LD -arch arm64 -syslibroot <iOS_SDK> -e _main -o c7ui_ios c7ui.o taes.o \
    -framework UIKit -framework Foundation -lc++ -lobjc -lSystem
```

注: zsh 下 `-mllvm -passes=$P` 必须整体引号或写字面值 (不做 word-split)。

## 五、签名证书状态 (2026-11-03)

- 开发证书 `Apple Development: zhou xinfei (GXJ853GX6Z)` **今日 (2026-11-03) 到期**
- 影响: 新 ipa 暂无法签名; 手机上已装的 6 个 app 不受影响 (已验证安装的签名仍有效, 可正常运行)
- 10-pass 版 3 个 iOS 二进制已导出至 `ios-device/unsigned-binaries/`, 证书续期后一条命令即可签名:
  ```bash
  python3 /Users/lasysloth/hap-debug-tool/ios_sign.py sign <打包的.app> \
      -i "<新证书>" -p <新profile>
  ```

## 六、测试状态总览

| 套件 | macOS | iOS 真机 |
|---|---|---|
| C v6 (5) | ALL PASS | ALL PASS (console + UI) |
| C++ v6 (6) | ALL PASS | ALL PASS (console + UI) |
| C v7 (5) | ALL PASS | ALL PASS (console + UI) |

累计 12 层 / 84 测试全通过 (v1–v7, macOS + iPhone 13)。


---

## 七、P2 补充导出（设备绑定 + 密钥分散, 2026-11-03 晚）

### 新增防护

**P2 — 设备绑定因子 (`tests/devbind.mm` + `wbaes_key.h` 钩子)**:
- 工作密钥 = 主分片 ⊕ 设备因子（32B）→ 二进制静态**无完整密钥、无可用分片组合**
- 因子 = FNV( Keychain半A ⊕ NSUserDefaults伪装项半B ⊕ 设备UUID派生 ⊕ SEP签名缓存halfS[仅iOS] )
- 三路分散: Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) + NSUserDefaults 伪装项 `last_metric_ts_seq` + SEP Keychain
- 换设备 → 因子不同 → 表重建后密钥不同 → **单设备破解不可复制**
- iOS SEP: EC256 Secure Enclave 密钥签名（首次生成→签名→缓存 Keychain，跨会话稳定）
- `WBAES_NO_DEVBIND` 编译开关 → 回退纯分片模式（密钥 d796fc6e...，与 openssl 互操作/标准向量验证用）

### P2 版产物（新增）

| 文件 | 说明 |
|---|---|
| `macos/wbaes_c_v7_test_p2devbind` | C v7 + P0/P1/P2 全防护 |
| `macos/wbaes_cpp_v6_test_p2devbind` | C++ v6 + 全防护 |
| `macos/wbaes_c_v6_test_p2devbind` | C v6 + 全防护 |
| `ios-device/unsigned-binaries-p2/c(6, 7)ui_ios, cpp6ui_ios` | iOS 全防护版（未签名，证书续期后签）|
| `src/devbind.h`, `src/devbind.mm` | 设备绑定源码 |

### 验证

- P2 版 macOS 三套件（全 10-pass 混淆）: ALL PASS ×2 次运行（因子稳定）
- iOS P2 二进制: 静态扫描无明文密钥 ✓
- 互操作模式（WBAES_NO_DEVBIND）: ALL PASS

### P2 后攻击面总结

| 攻击路径 | 状态 |
|---|---|
| 静态提取分片还原密钥 | **失效** — 缺设备因子，还原出的是错误密钥 |
| 拷贝二进制到其他设备 | **失效** — 因子不同，表完全不同 |
| LLDB/Frida 动态调试 | 延迟毒化 + 时间校验 + TEXT 校验三重拦截 |
| 内存 dump | 仿射已焚 + 因子在 Keychain/SE 不落内存明文 |
| DFA 数学攻击 | 双表双算 + 回环自检（已有）|

剩余攻击面: root 设备 + 无限时间逐设备逆向（客户端防御天花板）。

## 八、全量 SHA256 校验值

| 文件 | SHA256 (前16) |
|---|---|
| `macos/wbaes_c_v6_test` | aa5aca27c3a9316a... |
| `macos/wbaes_c_v6_test_p2devbind` | a58650001a97b0b1... |
| `macos/wbaes_c_v7_test` | c6c502d443732fef... |
| `macos/wbaes_c_v7_test_p2devbind` | f9310101e723996c... |
| `macos/wbaes_cpp_v6_test` | 85bfdfae9fee24cb... |
| `macos/wbaes_cpp_v6_test.id0` | 42649dc6369911bb... |
| `macos/wbaes_cpp_v6_test.id1` | c48a8c3a43371464... |
| `macos/wbaes_cpp_v6_test.id2` | 6cdabcf146436b96... |
| `macos/wbaes_cpp_v6_test.nam` | 39039b15bc1eb3d0... |
| `macos/wbaes_cpp_v6_test.til` | 1d484d7df6685002... |
| `macos/wbaes_cpp_v6_test_p2devbind` | c425838daae4aeea... |
| `ios-libs/libwbaes_cwrap_ios_arm64.a` | a032f289bcdde893... |
| `ios-libs/libwbaes_ios_arm64.a` | 13515799fd5fa09e... |
| `macos-libs/libwbaes_cwrap_macos_arm64.a` | bc01a2d037812fa1... |
| `macos-libs/libwbaes_macos_arm64.a` | 3a6d7c2d8216fe2d... |
| `ios-device/unsigned-binaries/c6ui_ios` | 08bd1524df809383... |
| `ios-device/unsigned-binaries/c7ui_ios` | e8d486707ae4de5b... |
| `ios-device/unsigned-binaries/cpp6ui_ios` | 67b7a6d389bf4b6e... |
| `ios-device/unsigned-binaries-p2/c6ui_ios` | 03a2fb7f2396ec01... |
| `ios-device/unsigned-binaries-p2/c7ui_ios` | 4b215b929a067140... |
| `ios-device/unsigned-binaries-p2/cpp6ui_ios` | 3e9d0a126f69861d... |
| `key/verify_key.py` | 5eac117acfde9161... |
| `key/wbaes_key.h` | 5c0f0e2aaef46a9b... |


---

## 九、P3 补充导出（DFA 自检 + 第三轨校验链, 2026-11-03 深夜）

| 文件 | 说明 |
|---|---|
| `macos/wbaes_c_v7_test_p3` | C v7 + P0/P1/P2/P3 全防护 |
| `macos/wbaes_cpp_v6_test_p3` | C++ v6 + 全防护 |
| `macos/wbaes_c_v6_test_p3` | C v6 + 全防护 |
| `macos/wbaes_dfa_selftest` | **DFA 故障注入自检**（4/4 PASS，可独立复跑验证防护有效性）|
| `src/test_dfa.cpp` | 自检源码 |
| `ios-device/unsigned-binaries-p3/*.ios` | iOS 全防护 UI 版 ×3（未签，证书续期后签装）|

P3 最终态: enc_core + dec_core 双向第三轨校验链（对称）+ 失配空转时序混淆（0..7 轮
随机伪计算，防 fault 轮号定位扫描）。自检覆盖: WB 全 plan 域故障拦截 / TF 非均匀
故障拦截 / decoy 陷阱毒化 / 基线往返 — 全 PASS。
