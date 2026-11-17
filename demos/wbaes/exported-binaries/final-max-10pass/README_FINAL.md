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

## 五、签名状态 (2026-11-03 晚 — 已解决)

- 旧证书今日 11:03 到期 → 11:06 装的 app 手指点击闪退 (SpringBoard 严格校验; 
  devicectl 启动走 debugserver 路径宽松所以当时误判正常)
- **已续期**: 新证书 (serial 70CC304F..., 有效期至 2027-11-03) + 新通配 profile
  (baee76be, "iOS Team Provisioning Profile: *", 通过 xcodebuild -allowProvisioningUpdates 刷新)
- **P3 全防护版 3 个 UI app 已重签 (v3.0-P3) → 安装 → 真机验证 ALL PASS (截屏 OCR 实证)**:
  - c6ui: 5/5 PASS (hashtable/bignum/base64/crc32/dlist)
  - cpp6ui: 6/6 PASS (stl/smartptr/factory/threadpool/exception/variant)
  - c7ui: 5/5 PASS (fsm/matrix/rd-parser/bitmap/heap), enc_cs 变化证实 P3 校验链生效
- `ios-device/*-signed.ipa` 已更新为 P3 新签名版 (可直接安装到本设备)

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


---

## 十、Hybrid Baked 全表路径（WBAES_BAKED 重写, 2026-11-04 → 11-11）

发布路径重写: 十轮全部进外部表 (`kHyTab`, 69,206,016 B)。运行时**没有 S 盒计算、
没有轮密钥异或**，只做下标散布后的查表:

- 表项 = 随机置换 (Q 网络) 后的列混合结果; 加密 9 轮 MC 合并轮 + 末轮 pair 表; 解密对称。
- 全部查表下标经 16 位 Feistel (`hy_scatter`) 散布 — 表内排列与明文下标不同域。
- **环境绑定**: 散布密钥 = `hy_env_mix(hw.pagesize, hw.ncpu, hw.cachelinesize)`，
  生成端与运行端各算一次。跨设备类别复制二进制 → 下标错位 → 输出垃圾
  （已实证: iPhone 类表 (16384/6/128) 的二进制在本机跑 FAIL）。
- 静态扫描 (`scan_leak.py`, 重组密钥+轮密钥扩展+自检测试向量): 全部二进制 **CLEAN**。
- iOS SDK 不公开 `sys/ptrace.h` — `demo_wbaes.cpp` 已按 `TARGET_OS_IPHONE` 分支手动声明。

### 本轮修复的潜伏 bug

`hw.cachelinesize` 是 **8 字节 sysctl**，`sizeof(int)` 缓冲 ENOMEM → 静默读成 0。
`gen_hybrid.cpp` 和 `demo_wbaes.cpp` 运行端同错同 0 → 之前一直"恰好一致"但环境指纹
缺 cacheline 维度。本轮两端都改 `unsigned long long` 读取，指纹恢复完整。

### 轮密钥卫生（用完即焚, 2026-11-11 → 11-12 扩展）

要求: 每一轮的密钥用完必须清除；进一步要求"最大可能用后即焚"。三处落实:

- **生成器 (`gen_hybrid.cpp`)**: 删除 `rk[11][16]` 常驻矩阵 → `derive_rk(r)` 按需正向派生
  （任意时刻内存中只有相邻两轮窗口，返回前烧毁）。加密每轮 `rk[r+1]` 随表写入完成即焚；
  末轮/解密入口的 `rk[10]` 各自用完即焚；解密每步 `rk[fwd]` 拷入 `folded` 后即焚、
  `folded`（InvMC 常量）随表写入完成即焚；解密尾部直接用主密钥；末尾逐轮
  "扫描表内无该轮密钥残留 → 立即焚毁该轮密钥"。主密钥在 `main` 统一焚毁
  （成功/失败路径都覆盖）。烧毁用 volatile 写阻优化器删除。
  **11-12 扩展**: ref_* 中间状态 `s` 焚毁; 编码结构 P/Pi（73KB, enc 末）、
  D/Di/Mperm/Minv（205KB, dec 末）、每轮 Q/Qi、每个 `outv`（含 sbox^RK10 等密钥分量）
  全部在最后消费点即焚。
- **运行时非 BAKED 开发路径 (`demo_wbaes.cpp`)**: 解密块窗口原本已焚；
  补齐加密块 — FT（最后一次用 RK10）后窗口焚毁，与解密块同一纪律。
  **11-12 扩展**:
  - `rk_next_word` 的 g() 输出 `t[4]` 即焚; `g_plan_rng`（密钥派生 seed）plan 建完即焚;
  - `init_tables` 尾: `sk_eff`/`seed` 栈副本焚毁（`sk`/`half_b` 在 `init` 尾焚,
    正本 `session_half_a`/TLS 按设计存续）;
  - 标准 SBox/InvSBox 栈临时 `sb_std`/`iv_std` 用完焚毁（数据段已无指纹, 栈也不留）;
  - **运行期随机源隔离**: 陷阱抽查/垃圾输出改 `wb_runtime_rand()`（系统熵源）,
    不再推进密钥派生 PRNG — splitmix64 全程可逆, 旧实现下读若干垃圾输出字节
    即可反推 PRNG 状态 → 重推 init 期全部仿射编码; 该反推链现已闭合。
    init 结束后 `wb_prng_state` 焚毁;
  - `WBAES_DYNAMIC_KEY` 注入分片 init 完成即焚 + `g_dyn_ready=0`（二次 init 必须重新注入）。
- **BAKED/hybrid 运行时**: 无轮密钥物化（十轮全在表内），天然满足。

`wbaes_key.h` 的 `verify_shards`/`key_byte` 均为寄存器内逐字节重组，无 16B 连续形态，不需要额外处理。
注: 非 BAKED 开发版按设计含密钥分片与 `tiny_aes.c` 标准 SBox（交叉验证参照）, 静态扫描
预期 sbox16 命中; 发布版 BAKED 三件套（mac plain/9-pass/iOS）全部 CLEAN。

### 生成与构建

> 换钥（替换 AES-128 主密钥）的完整流程见 `demos/wbaes/KEY-ROTATION.md`：
> `rotate_key.py` 改写分片与自检向量 → `gen_hybrid` 重新生成表 → 重链接 → 自检。
> 表即密钥，**只改 `wbaes_key.h` 而不重新生成表，二进制仍是旧钥**。

```bash
cd /tmp/wbaes-hybrid-build
CL=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/src/build/bin/clang++
W=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/demos/wbaes

# 1) 生成表 (缺省读本机 sysctl; 交叉生成用 --pagesize/--ncpu/--cls 指定目标设备类别)
clang++ -O2 -std=c++17 -I$W $W/gen_hybrid.cpp -o gen_hybrid
./gen_hybrid khytab.bin                          # 本机 (自检: table-check + seal-check PASS)
./gen_hybrid khytab_ios.bin --pagesize 16384 --ncpu 6 --cls 128   # iPhone 类

# 2) 表进链接: .incbin (Section __DATA,__const, globl _kHyTab)

# 3) macOS 二进制 (arm64 注意: ccc 仅 x86, 不能进 pass 列表 — 见下)
$CL -O2 -std=c++17 -DWBAES_BAKED -I$W $W/demo_wbaes.cpp khytab.S \
    -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla,merge -o wbaes_baked_10pass

# 4) iOS 两段式
SDK=$(xcrun -sdk iphoneos --show-sdk-path)
$CL -arch arm64 -isysroot $SDK -mios-version-min=16.0 -O2 -std=c++17 -DWBAES_BAKED -I$W \
    -c $W/demo_wbaes.cpp -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla,merge -o demo_baked_ios.o
clang -target arm64-apple-ios16.0.0 -isysroot $SDK -c khytab_ios.S -o khytab_ios.o
LD=$(xcrun -sdk iphoneos -f ld)
$LD -arch arm64 -syslibroot $SDK -platform_version ios 16.0 16.0 -e _main \
    -stack_size 0x800000 -o wbaes_baked_ios demo_baked_ios.o khytab_ios.o -lc++ -lSystem
codesign -s - wbaes_baked_ios
```

注 (勘误): 第三节的 10-pass 列表 `...,ccc,merge` 中 **ccc 只支持 x86** — arm64 目标
(macOS arm64 / iOS) 实际可用列表为 `alias,gvenc,indcall,indbr,mba,sub,bcf,fla,merge`
(9-pass)，本节产物即此列表。普通 clang 编译 BAKED 路径需加 `-DWBAES_NO_MIR`。

### 验证结果 (2026-11-12, 含 iPhone 真机)

| 项 | 结果 |
|---|---|
| gen_hybrid 自检 (table-check + seal-check + 8 随机向量回环) | PASS |
| 非 BAKED 开发路径 (wbaes_dev_test): vector-match + roundtrip | PASS |
| DFA 自检 (test_dfa, 真随机化后 ×4 次运行) | 4/4 PASS |
| macOS BAKED plain (`wbaes_baked_test`): vector-match + roundtrip | PASS |
| macOS BAKED 9-pass (`wbaes_baked_hybrid_10pass`): 同上 | PASS |
| **iOS 模拟器** (iPhone 16 Pro sim, arm64, host 表): vector-match + roundtrip | PASS |
| **iOS 模拟器负测试** (iPhone 类表 16384/6/128): 表失配 → 垃圾输出 | 失效 (预期) |
| **iPhone 真机 (iPhone 8 / iPhone10,1 / iOS 13.6)**: 9-pass + baked 表, ×2 次运行 | **vector-match + roundtrip PASS** |
| 真机 env 实证: `hw.pagesize=16384 ncpu=6 cls=128` (A11/iOS13 也是 16K 页!) | 与表一致 |
| 静态扫描: 发布版 (mac plain / mac 9-pass / iOS 真机版) 密钥+全轮密钥+SBox 指纹 | CLEAN ×4 |
| 静态扫描: 开发版 (dev_test) | 仅 sbox16 命中 = tiny_aes.c 参照表 (设计内) |
| 环境绑定负测试 (iOS 表二进制跑在本机 / iPhone8 表假设 4096/6/64) | 失效→垃圾输出 (预期) |

### 产物

| 文件 | SHA256 (前16) |
|---|---|
| `hybrid-baked/macos/wbaes_baked_hybrid_10pass` | 803b22e2961a173a... |
| `hybrid-baked/ios-device/wbaes_baked_ios_unsigned` (min iOS 16) | 5f9f132112c86f01... |
| `hybrid-baked/ios-device/wbaes_baked_ios13_ip8_unsigned` (min iOS 13, **真机已验证**) | f92fa7cb8046a186... |
| `hybrid-baked/scan_leak.py` | 验证工具 (重组密钥扫描, 不回显密钥) |

### 真机验证流程 (iPhone 8 / iOS 13, 2026-11-12)

```bash
# iPhone10,1 (iOS 13.6) — devicectl (CoreDevice) 不支持 iOS<17, 走 libimobiledevice
./gen_hybrid khytab_ios.bin --pagesize 16384 --ncpu 6 --cls 128   # 真机 env 上报对齐
# 编译: -mios-version-min=13.0 -DWBAES_IOS_RESULT_FILE (结果写沙盒 Documents/result.txt)
ideviceinstaller -u <UDID> install wbaesbaked8.app
idevicedebug -u <UDID> run JMD2JV9294.wbaes.baked.test8           # 拉起 (退出码45=debugserver脱钩, 无害)
afcclient -u <UDID> --container JMD2JV9294.wbaes.baked.test8      # house_arrest 拉结果
#   get Documents/result.txt →  vector-match: PASS / roundtrip: PASS
```

注意: `-DWBAES_IOS_RESULT_FILE` 下 main 先打印 `device-env: pagesize/ncpu/cls`
（本机原始参数上报, 非密钥）— 环境绑定假设错了可以一步对齐, 不用盲试。
本轮教训: A11/iOS13 并非 4K 页 — hw.pagesize 实测 16384, 与 iPhone 15 类同表。

待办: 现代真机 (iPhone 13/15, devicectl 路径) 未重验 — 表已含 16384/6/128, 预期一致;
UI 版 ipa (test_c*_ui.mm 内嵌 `demo_wbaes_noasm.cpp`) 切换 BAKED 路径需改内嵌为
`demo_wbaes.cpp -DWBAES_BAKED` 并链 kHyTab — 真机验证已通过, 可随时切。

模拟器注: sim 进程继承宿主 sysctl (16384/10/128)，所以模拟器只验证 iOS 用户态
运行路径；环境绑定需真机参数。模拟器构建命令 = 上面 iOS 两段式，把
iphoneos → iphonesimulator、`arm64-apple-ios16.0-simulator`，驱动直链即可 (无框架依赖)。
