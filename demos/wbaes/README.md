# 白盒 AES-128 Demo（Chow-style T-table，单密钥烘焙版）

## 0. 密钥记录（唯一密钥源：`wbaes_key.h`）

| 项目 | 值 |
|---|---|
| 密钥（hex） | `3ae9dfcb63087f5e4ef82fd5daf48eab` |
| 长度 | AES-128（16 字节） |
| 生成方式 | `openssl rand -hex 16` |
| 生成日期 | 2026-10-29 |
| 存放位置 | `demos/wbaes/wbaes_key.h` —— **全仓库唯一明文密钥** |
| 自验明文 | `6bc1bee22e409f96e93d7e117393172a` |
| 自验密文 | `7e5232eeaad5b1b17f7a5c009037225d`（pycryptodome AES-128-ECB 预计算，已 openssl 交叉验证） |

**设计原则**：明文密钥只存在于 `wbaes_key.h` 一处，且仅用于**编译期**生成查找表。
密钥以 `key = key_part ⊕ key_mask` 两片分 XOR 存储（volatile 读取阻止编译器
常量折叠回明文），**二进制中密钥明文序列出现 0 次**（16B 与全部 8B 片段均已扫描）。

**计算过程中原始密钥不出现**（2026-10-30 强化）：
- 手写 KeyExpansion（FIPS-197 5.2 内联版）直接以分片为输入，密钥字节
  `ldrb + eor` 逐字节寄存器内重组（反汇编已审计），**全程无 16B 连续明文缓冲落地**
- 旧实现 `get_key(k)` 重组完整 16B 到栈再喂 `AES_init_ctx` —— 已移除
- PRNG（编码矩阵派生）seed 改用 `key_part`（part 单独 ≠ 原始密钥）
- 首轮 ARK(0) 字节 `key_byte(i)` 寄存器内逐字节 XOR，无缓冲
- 运行时（encrypt/decrypt）查表路径无任何密钥形态数据；init 结束后
  轮密钥 RK（派生物）即弃
- 表内完整密钥/轮密钥 16B 序列出现 0 次（逐轮扫描已验证）

⚠️ 本 demo 密钥仅用于测试。生产环境的密钥应通过 KMS/安全通道注入，
烘焙后的表数据随固件/应用分发前需再做一层外壳保护。

## 1. 文件

| 文件 | 说明 |
|---|---|
| `wbaes_key.h` | 密钥唯一来源 + 自验向量。换密钥只改这里，两个 demo 一起重编 |
| `demo_wbaes.cpp` | 完整版：encrypt/decrypt 带 `sub,bcf,fla` 标注 + `asm("backend-obfu")`（MIR 触发） |
| `demo_wbaes_noasm.cpp` | plain/IR 对照版：无标注无 asm（Polaris IR pass 与 MIR 均不触发） |
| `aes.h` / `tiny_aes.c` | kokke/tiny-AES-c（MIT），仅用其 KeyExpansion 与 ECB 做交叉验证 |
| `tiny_aes.o` | tiny_aes.c 预编译产物（可删，重编会重新生成） |
| `wbaes_vm.cpp` / `wbaes_vm.h` | HSV 字节码程序（每轮 16 个表偏移）+ 宿主侧封装。**只有这个 TU** 用 `-mllvm -passes=hsvm` 编译 |
| `wbaes_hybrid.h` / `wbaes_hybrid.inc` | 表网络与热路径；`WBAES_HAVE_VM` 打开后表地址取自 VM 返回的偏移 |
| `bench_wbaes.cpp` | 每块加解密耗时（`#define WBAES_NO_MAIN` + include demo TU，测的就是发布路径） |
| `tests/test_vm_offsets.cpp` | VM 偏移 vs C 参考实现（含非本机布局字，证明常量没有被烘进字节码） |

## 2. 白盒原理

AES 轮 = SubBytes → ShiftRows → AddRoundKey → MixColumns。
白盒化把整轮合并进查找表，密钥不再以变量形式存在；
在此基础上叠加 **Chow 外部编码**（见 2.5）破坏裸 AES 表结构：

### 加密方向（160KB 表）

```
WB[r][kk][j][x] = MC_col( SBox[x ^ a0], kk ) ^ ( RK[r+1][4j+kk] << (24-8kk) )
  r  = 轮号 0..8（前 9 轮）
  kk = 输入行（0..3）
  j  = 输出列（0..3）
  x  = 表输入字节（该位置 ShiftRows 后的源字节）
  a0 = ARK(0) 烘焙：仅 r==0 时取 key[4*((j+kk)%4)+kk]，其余轮为 0
  rk = ARK(r+1) 输出字节，烘在 MixColumns 输出侧
TF[kk][j][x] = ( SBox[x] ^ RK[10][4j+kk] ) << (24-8kk)   末轮（无 MixColumns）
```

- **ARK(0)** 烘进首轮表 SBox 输入侧（`x ^ a0`）——首轮表输入是明文字节
- **ARK(1..10)** 烘在 MC 输出侧按字节 XOR。注意 **ARK 不可并进 SBox 输出侧**：
  MixColumns 线性但系数 ≠ 1，`MC(sb ^ rk) ≠ MC(sb) ^ rk_bytes`（开发中踩过的坑）
- 运行时每输出列 4 次查表 XOR 合并，ShiftRows 由查表下标 `(j+kk)%4` 完成

### 解密方向（176KB 表，tiny-AES InvCipher 同构）

```
逆链: ct → ARK(10) → 9×[InvSR + InvSB + ARK(RK[9-r]) + InvMC] → [InvSR+InvSB+ARK(0)] → pt

FT[kk][j][x]   = ( x ^ RK[10][4j+kk] ) << (24-8kk)     原位 ARK(10)，纯 XOR 表
DWB[r][kk][j][x] = InvMC_col( InvSBox[x] ^ RK[9-r][4j+kk], kk )   逆轮 9..1
DTF[kk][j][x]  = ( InvSBox[x] ^ RK[0][4j+kk] ) << (24-8kk)   末逆轮（无 InvMC）
```

- 查表下标 `(j-kk+4)%4` 的地址变换即逆 ShiftRows（InvSR）
- 逆轮 r=0..8 对应逆链轮 rnd=9-r，ARK 取 `RK[9-r]`（tiny-AES `round = Nr-1..0` 起始——
  即第一逆轮 ARK = RK[9]，与 FIPS 5.3.5 等效逆密码的 Kd 索引不同，以 tiny-AES 实测为准）
- **中间轮 Ark 不可做 InvMixColumns 预变换**：本实现 ARK 在 InvMC 之前（输入侧），
  与"等效逆密钥 Kd"路线（ARK 在 InvMC 后需 InvMC 变换）不同，两条路线等价但不可混用

### 2.5 外部编码（external encoding，抗静态表分析）

每轮输出状态经仿射 `A_r(y) = M_r·y ⊕ c_r`（M_r: 8×8 GF(2) 可逆矩阵，
由密钥派生 splitmix64 PRNG 生成并消元验证可逆）。编码链**全部烘进表内**，
运行时查表路径与无编码版完全相同，零额外开销：

```
WB'_r[kk][j][z] = A_r'( WB_r[ A_{r-1}^{-1}(z) ] )
  输入侧: 索引重排吸收上一轮编码 (查表地址变换即解码)
  输出侧: A_r' 逐字节作用在 MixColumns 输出 4 字节上
  常量分摊: c_r 只放在 kk==3 那张表 → 4 表 XOR 合并后恰为完整 A_r
            (4 表都放 c 则 c⊕c⊕c⊕c = 0 抵消 — 踩过的坑)
TF'[kk][j][z] = TF[ A_8^{-1}(z) ]   末轮输出无编码 (密文必须原域)
解密侧对称: 独立仿射组 B_r (同一 PRNG 续流), 链式同构
```

效果：表数据中裸 SBox/MixColumns 轮廓被仿射打散，表压缩/代数分析第一步失效；
换密钥 ⇒ 编码矩阵全变 ⇒ 表数据完全不同（编译期随机化）。
边界：仿射编码是线性的，**不抵抗 DFA（差分故障分析）**——抗 DFA 需要
非线性双射编码 + T-box/混合双射分离（生产化方向）。

### 2.6 AES 指纹消除（S 盒/轮常量打散）

标准 AES 的静态指纹及消除方式（全部编译期完成，运行时零开销）：

| 指纹 | 位置 | 消除方式 |
|---|---|---|
| SBox 256B 常量 | 数据段（yara/strings 秒识别） | **数学生成**（FIPS-197 3.2 定义式）：`SBox(x) = affine(x^-1)`，GF 逆暴力查证 + 位旋转仿射，**源码与二进制均无 S 盒字节**；生成值再经密钥派生仿射 `A_s` 打散为 `SBOX_S`，表构造处 `aff_inv` 恢复 |
| InvSBox 256B | 数据段 | 同上（栈上逆查表生成 → `A_i` 打散 → `INV_S`） |
| RCON `{01,02,04..36}` | 数据段 | 运行时 GF(2^8) 乘方生成 `rcon_gen(r)`，无表 |
| 约减常数 0x1b | 代码段 | 拆为 `0x1c ^ 0x07` 两常量异或；SBox 仿射常量 0x63 拆为 `0x60 ^ 0x03` |
| MC 系数 {2,3}/{14,11,13,9} | 代码段 | 保留（GF 乘法函数内联，Polaris sub/mba 已打散） |
| 类/函数符号 `WBAES`/`AES_*` | 符号表 | 生产版 strip（见下） |

演进说明：第一版用"双片异或存储"（`SBOX_DATA ⊕ SBOX_XMASK`）——单片无特征
但两片仍在二进制中，识别出 XOR 模式仍可重组；当前版**彻底删除**全部 S 盒
静态数据，只留 GF 乘法/位旋转代码，逆向者只能看到"一段计算"，无从知道
它生成 S 盒（除非理解 FIPS 定义式）。

**验证**（WBAES_PROD_CLEAN，2026-10-30）：标准 SBox/InvSBox 256B、前 16B 短签名、
RCON 序列、密钥 16B/8B 片段——全部 **0 命中**。

### 2.7 生产版编译（去符号 + 去 ECB 参考）

demo 版含 tiny-AES ECB 参考（自验用），其内部也有 SBox 常量——**生产版不要链接它**：

```bash
# 纯白盒生产版: 无 ECB 参考、无指纹常量、符号全 strip
# 关键: -Wl,-exported_symbols_list,<空文件> 去掉全部全局符号 (WBAES_*/AES_*)
touch /tmp/empty.exp
clang++ -O2 prod_main.cpp -Wl,-x -Wl,-s -Wl,-exported_symbols_list,/tmp/empty.exp -o wbaes_prod

# ⚠️ 不要用 post-hoc `strip` — 破坏 codesign 导致 SIGKILL (实测), 必须链接期完成
```

### 已修复的关键坑（重写时勿回退）

1. **ARK 位置**：加密侧 ARK 必须在 MC 输出侧按字节 XOR；解密侧 ARK 在 InvSB 输出侧
2. **逆链 ARK 索引**：`DWB[r]` 用 `RK[9-r]`（r=0 → RK[9]），不是 RK[8-r]
3. **FT 纯 XOR**：FT 段只做原位 ARK(10)，不做 InvSR/InvSB——否则后续 DWB 查表的
   地址变换（InvSR）会二次移位、DWB 表内 InvSBox 会双重逆 S 盒
4. **FT/DWB/TF 段输出必须经 `ns` 暂存再回写**：列 j 的输出直接写 `st[j]` 会污染
   尚未处理的 j+1..3 的 ShiftRows 查表输入（in-place 覆盖 bug，加密末轮与解密
   FT 段各踩过一次）
5. **编码常量 c_r 只放 4 表中的 1 张（kk==3）**：4 表 XOR 合并会抵消重复常量
6. **仿射求逆的高斯消元列序必须与 aff_fwd 位约定同向**（bit col 起主元）；
   用 bit7 起列会得到转置修正后的"错逆"（A^-1(A(x)) ≠ x），需全 256 值自验
7. **密钥分片存储必须 volatile 读取**：否则 -O2 常量折叠把 `part^mask`
   折回明文密钥，二进制残留 16B 序列

## 3. 烘焙流程（换密钥 SOP）

1. 生成新密钥：`openssl rand -hex 16`
2. 编辑 `wbaes_key.h`：更新 `key[16]` 字节数组
3. 用 pycryptodome（或 openssl）预计算自验密文，更新 `test_ct[16]`：
   ```python
   from Crypto.Cipher import AES
   ct = AES.new(bytes.fromhex('<new_key>'), AES.MODE_ECB).encrypt(bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'))
   print(ct.hex())
   ```
4. 重编两个 demo（`demo_wbaes.cpp` 与 `demo_wbaes_noasm.cpp` 都从 `wbaes_key.h` 取密钥）
5. 跑自验（见下节），`vector-match` 与 `roundtrip` 均 PASS 即完成

## 4. 编译与验证

```bash
# 系统 clang（语义验证）
clang++ -O2 demo_wbaes.cpp tiny_aes.c -o wbaes_test
./wbaes_test    # 期望 vector-match PASS + roundtrip PASS

# Polaris（plain，无任何混淆——用 noasm 源）
clang++ -O2 demo_wbaes_noasm.cpp tiny_aes.c -o WBAES_PLAIN

# Polaris（IR 混淆）
clang++ -O2 demo_wbaes_noasm.cpp tiny_aes.c -mllvm -passes=sub,bcf,fla -o WBAES_IRONLY

# Polaris（IR + MIR，asm 标记触发后端混淆）
clang++ -O2 demo_wbaes.cpp tiny_aes.c -mllvm -passes=sub,bcf,fla -o WBAES_MIR
```

### 验证结果（2026-10-30，外部编码版）

| 检查项 | 结果 |
|---|---|
| NIST 向量比对（预计算密文） | PASS（plain / IR / MIR 三档二进制全过） |
| 加解密回环 | PASS（同上） |
| 32 组随机明文 vs tiny-AES ECB 交叉验证 | 32/32 PASS |
| 表内完整 16B 密钥序列出现次数 | **0** |
| 表内 11 个轮密钥 16B 序列出现次数 | **0**（逐轮扫描） |
| 旧 NIST 密钥 `2b7e1516...` / 旧 ark10 `d014f9a8...` 残留 | **0** |
| 二进制中密钥明文出现次数 | **0**（分片 XOR 存储 + volatile 阻折叠） |

表体积：加密 160KB + 解密 176KB = **336KB**（含 FT/DTF 后比旧版 320KB 多 16KB——
解密侧拆出独立 FT/DTF 表以修复双重 InvSBox bug）。

二进制体积对比（`exported-binaries/ida-compare-pair/`）：

| 产物 | 大小 | T 符号数 |
|---|---|---|
| WBAES_PLAIN | 51,528 B | 13 |
| WBAES_IRONLY（sub+bcf+fla） | 51,536 B | 13 |
| WBAES_MIR（IR + MIR） | 68,408 B | 13 |
| WBAES_PROD_CLEAN（纯白盒生产版，strip） | 33,808 B | 1（仅 mh_execute_header） |

### 可选：函数数量虚增（未应用于当前产物）

`fake_symbols.py` 可对任意 MIR 产物做符号表后处理（注入伪符号 + 重建
LC_FUNCTION_STARTS + 置零 unwind_info），IDA 实测可把函数从 13 虚增到 387。
按需选用：

```bash
python3 fake_symbols.py <mir_binary>
codesign -f -s - <mir_binary>
```

当前导出的 `WBAES_MIR` **未应用**该处理，保持编译器原始输出。

## 5. 抗提取防护（针对已公开 writeup 攻击链, 2026-10-30）

实际 writeup（LLDB 动态改写 + 分片 XOR）暴露的攻击链及逐环加固：

| 攻击环 | writeup 手法 | 加固对策 | 复测 |
|---|---|---|---|
| 1 已知明文定位 | 程序自打印 test_pt/ct, 常量在 `__const` 紧邻密钥分片 | 向量与密钥区彻底分离（分区存放） | `test_pt` 邻接 16B 是 `test_ct`, 非密钥 ✓ |
| 2 相邻分片 XOR | 两个 16B 份额相邻存放, `S1⊕S2` 即密钥 | 密钥拆 4 片 ×4B, part/cover 分别嵌入 **64B 随机块的随机偏移**（part0↔cover0 距 264B）, 邻接 XOR 得 decoy | writeup 脚本原样跑 → 输出 `1b44b757...` 垃圾 ✓ |
| 3 动态改写反馈 | LLDB 改写份额 → 清零得全零密钥密文（语义反馈确认猜对） | 每片 FNV 校验字（嵌块内随机偏移）, 改写 → 校验失败 → seed 污染 → 表失真 → **输出乱码无语义反馈** | 静态改写测试 + 表失真路径 ✓ |
| 4 调试器 | LLDB attach 自由调试 | **静默错误分支**：`sysctl` 检测 `P_TRACED` → 毒化 SBOX_S/INV_S → 表失真 → 输出乱码；运行中每次加解密前轮询 → 置位后门面直接输出 PRNG 垃圾 | attach 后进程"正常跑"但输出全错，且与分片改写/DFA 拦截不可区分 ✓ |

另: 分片读取为跨块寄存器内逐字节 XOR（`ldrb+eor`）, 无 16B 连续形态;
分片改写同时污染双轨表 seed（ tampered 位混入）, 与 DFA 双轨防护联动。

**教学边界**: 分片数据仍在同一二进制内, 熟练逆向（识别 64B 块引用链）仍可还原 —
提高攻击成本非绝对防护。生产环境密钥应经 KMS/白盒密码学方案注入。

## 6. DFA 防护（双轨冗余）

**DFA（差分故障分析）**是白盒 AES 的头号动态攻击：对最后一轮注入故障，
收集若干 (正确密文, 故障密文) 对做差分即可恢复末轮轮密钥，进而逆推全密钥。

防护方案：**双轨冗余**（spatial redundancy）

```
WBAES 内含两套表 t1/t2 (各 336KB, 共 672KB):
  链 1: 编码/仿射由 key_part 派生 PRNG 生成
  链 2: 编码/仿射由 key_mask 派生 PRNG 生成  ← 两链完全独立
encrypt/decrypt: 双轨各算一次 → 比对一致才输出;
  不一致 (故障注入迹象) → 输出 PRNG 随机垃圾, 且每次不同
```

- 单表故障：两轨结果不一致 → 拦截，攻击者拿到的是无差分价值的随机垃圾
- 两次同故障输出互异 → 无法积累有效差分对 → DFA 失效
- 绕过条件：攻击者需**同时**对两套表注入位姿一致的故障（需精确控制
  故障位置/时序/值，实践难度数量级提升）
- 代价：表内存 ×2（672KB），计算量 ×2

**实测**（2000 个表项采样位翻转注入）：hit=8, 拦截=8, 泄漏=0 —— DFA 差分收集被完全阻断。

残余风险（教学版边界）：双轨比对的 memcmp 本身可能被故障攻击（跳过比对分支）；
彻底方案是比对也双轨化/容错编码。非线性编码（真抗 DFA 的 Chow 完整方案）仍是生产化方向。

## 5.5 反调试：静默错误分支

设计原则：**检测到调试器不退出、不报警**——退出/崩溃是显式信号，攻击者立刻知道
"防护命中"并寻找绕过；静默走错误分支让攻击者无法区分"输出错误"来自哪层防护
（分片改写校验、DFA 双轨比对、还是反调试），失去定向调试的反馈。

```
检测: sysctl(KERN_PROC_PID) → kinfo_proc.kp_proc.p_flag & P_TRACED
时机: ① init 中 S 盒生成后 (毒化 SBOX_S/INV_S → 两链全部表构造用毒化值)
      ② 每次加解密前轮询 (防运行中 attach) → 置 0x8000 位 → 门面直接输出 PRNG 垃圾
错误分支: 与分片改写故障 / DFA 双轨失配的输出完全同形 — 无差别降级
```

实测：`调试位命中后输出乱码 ✓, 清位恢复 PASS ✓`。
边界：P_TRACED 只检测已 attach 的调试器；内核级调试/启动前断点需额外方案
（如 sysctl 轮询线程、代码校验和），且任何用户态反调试都可被内核态绕过。

## 5.7 密钥存储方案矩阵（针对"分片在 __TEXT,__const 可被静态重组"的根治路径）

writeup 已证明：**只要密钥派生所需的全部数据都在客户端二进制内，静态分析理论可提取**
（信息论边界，任何拆分/打散/XOR/校验都只是提高成本）。真正改变威胁模型的方案：

| 方案 | 二进制内密钥数据 | 抗静态提取 | 抗内存 dump | 离线可用 | 实现状态 |
|---|---|---|---|---|---|
| 静态分片（当前默认） | 有（打散+校验+反调试） | 提高成本，非根治 | 白盒本体 | ✓ | `wbaes_key.h` 静态模式 |
| **动态注入**（方案 B） | **零**（分片由服务器 per-device 下发） | **彻底** | 白盒本体 + 会话加密表 | 需首次联网 | `WBAES_DYNAMIC_KEY` 编译开关（已实现） |
| 硬件绑定（方案 C） | 分片+设备指纹复合 | 彻底（拷走无用） | 白盒本体 | ✓ | Secure Enclave（未实现，需硬件） |
| 服务器端加解密（方案 A） | 无白盒 | — | — | ✗ | 超出白盒范畴 |

### 动态注入用法（已实现）

```cpp
// 服务器侧（激活时 per-device）:
//   part[s][b] = key[s*4+b] ^ cover[s][b]   (cover 服务器随机生成)
// 客户端:
#include "demo_wbaes.cpp"   // 编译加 -DWBAES_DYNAMIC_KEY
uint8_t part[4][4], cover[4][4];   // 从服务器响应解析
wbaes_inject_key(part, cover);     // init() 之前调用
WBAES wb; wb.init();               // 表用注入分片生成

// 未注入即运行 → 表全垃圾 → 输出乱码（静默，无语义反馈）
```

配合已实现的会话加密驻留（表密文在内存、会话 key 每次启动随机），
动态模式下：静态提取 **零数据**，内存 dump 得到的是密文表且每次不同。

## 5.8 针对 WRITEUP(1) 固定索引 DFA 的加固复盘

WRITEUP(1) 用"Unicorn 模拟单轨 core + 固定索引 fault 注入 round8 表项"恢复末轮
密钥 → 反推主密钥。暴露的薄弱点及本轮加固：

| 薄弱点 | writeup 手法 | 加固 |
|---|---|---|
| LC_FUNCTION_STARTS 未清 | 解析出全部 7 个函数地址 | 链接 `-Wl,-no_function_starts` 剥除（0 残留）|
| 双轨在 wrapper 层 | 直接模拟单轨 `enc_core` 绕过比对 | **双轨下沉到轮级**：`enc_core(t1,t2,...)` 每轮两轨各算+比对，单表故障本轮即拦截 |
| 反调试单点可 patch | patch 3 处条件跳转，patch 后输出正确 = 免费 oracle | **交叉链**：3 检测点读数互校，单点 patch 被其余点发现；读数变化触发 S 盒材料翻转 |

轮级双算后 fault 注入实测（2000 表项采样）：hit=8, 拦截=8, **泄漏=0**。
攻击者要产生有效 fault 对，必须让两轨**同时**出现位姿一致的故障——需要精确的
双注入协同，Unicorn 单轨模拟路线被关闭。

残余边界：轮级双算使计算量 ×2；攻击者若能同时 hook 双轨的 dec() 仍可对齐
（需内核级 hook，成本再次提升）。

## 5.9 反 Unicorn 模拟（TLS 绑定会话 key）

WRITEUP(1) 用 Unicorn 模拟单轨 core 实现高速 fault 采样。模拟的本质优势：
脱离真实进程运行时状态。对策：**会话 key 绑定 pthread TLS**。

```
表加密 key = half_a ⊕ half_b
  half_a: 存表结构 (内存 dump 可得)
  half_b: 存 pthread TLS (槽 0) — 需 TPIDRRO_EL0 上下文才能定位
dec() 每次从 TLS 读 half_b → 地址绑定解密
```

Unicorn 模拟路线的困难：
- 纯表 dump + 模拟 → 缺 half_b → 全部表项解密错 → 输出乱码
- 要模拟成功必须复现 TLS：设置 TPIDRRO_EL0 并填充对应槽内容 —
  需要先 dump 真实进程的 TLS 内存（比表 dump 多一个环节，且 TLS 内容
  每次进程启动不同，无法用旧 dump）
- 进程内轮询反调试仍在：attach 状态下 dump 的表是毒化产物

实测：三次运行 dump 表区 FNV 哈希全不同（会话加密生效）；
正常路径/32 组随机/DFA 拦截全 PASS。

残余边界：攻击者 dump TLS 后在 Unicorn 中重建 TLS 上下文仍可模拟 —
但每一步成本都在叠加（表 dump → TLS dump → 反调试 patch → 双轨对齐）。

## 5.10 轮差异化与回环自检（针对 WRITEUP(1) DFA 的第二层）

WRITEUP(1) 的固定索引 DFA 依赖两个前提：**故障密文可收集** + **恢复的末轮密钥
可按标准 key schedule 反推**。本轮加固直接打击这两个前提：

### 末轮输出编码 Q_10（切断反推）

TF 表输出 = Q_10(密文)（PRNG 续流生成的仿射，常量按 kk==3 分摊），
encrypt 出口用 `aff_inv` 剥离。DFA 固定索引法恢复的"末轮密钥"是 Q_10 编码域
的伪密钥——反推 key schedule 得到的"主密钥"验证失败，writeup 第 5 步被切断。

（实现坑：4 表 XOR 会抵消重复常量——Q_10 的常量只放 kk==3 表，与 WB 的分摊手法相同。）

### 回环自检（切断 fault 对收集）

```
encrypt(pt):
  ct = 轮级双算 (单表 fault 本轮即拦截)
  back = decrypt(ct)
  back != pt → 输出 PRNG 垃圾 (fault 密文不外泄)
```

实测（2000 表项采样）：
- 单轨 fault：轮级拦截，hit=8 拦截=8
- **双轨同位 fault**（强攻击者，精确双注入）：hit=8，回环自检拦截=8，泄漏=0

两层防护叠加后，即使攻击者实现精确双注入，fault 密文仍无法外泄——
固定索引 DFA 的数据收集阶段被完全阻断。

### 轮结构差异化的已具备部分

- 每轮轮间编码 Q_r 独立（writeup 已确认"各表编码独立，DCA 不可行"）
- 末轮 Q_10 输出编码（本轮新增）
- 轮密钥流式生成、S 盒数学生成、表内存加密——整体结构与教科书 AES 表白盒
  （21-block×16 表固定布局）已不可对齐

## 5.11 轮计划表与跳转栈化

**轮计划表（block 乱序）**：密钥派生 PRNG 生成 Fisher-Yates 置换 WB_PLAN/DWB_PLAN，
轮 r 的表存于乱序槽位（构造与运行时一致使用映射）。dump 后的表布局与
"标准 AES 10 轮 × 16 表"模型不可对齐，writeup 式"block r = 轮 r"建模需先恢复映射。

**跳转栈化**：core 调用经栈上 volatile 函数指针间接执行（非直接 BL 符号跳转），
配合 fla 的 switch 跳转与 indcall/indbr，静态提取调用图进一步困难。

（注意：两链必须共享同一 plan——若各链独立乱序，运行时查表将错位。）

## 5.12 查表随机化、表类别绑定与陷阱表

| 优化 | 机制 | 打击的攻击 |
|---|---|---|
| 查表顺序随机化 | 每会话 PRNG 生成 kk 遍历序 (XOR 可交换 → 输出不变) | Unicorn trace 的查表序列建模：每会话访问序不同，无法积累稳定的 trace 模板 |
| 表类别绑定解密 | dec()/enc() 的 keystream 混入表类别因子 (WB/TF/FT/DWB/DTF 各异) | 表项重定位攻击：把 A 表项搬到 B 表位置 → 解密错 |
| 陷阱表 | 表区尾部 32KB 加密哨兵 (无合法查询路径)，每次 encrypt 随机抽查一项 | 盲扫/hook 表访问/批量 patch 表区：波及陷阱 → 毒化输出 |

## 5.13 多语言测试矩阵

`tests/` 目录覆盖 C/C++/ObjC/ObjC++ 四种语言 × 复杂语法 × 白盒 AES 集成:

| 语言 | 语法覆盖 | 全 pass+MIR | 语义 |
|---|---|---|---|
| C | 函数指针表/变长参数/位域/union/递归链表/goto 状态机/柔性数组 | 69,736B | 5/5 PASS |
| C++ | CRTP/变参模板/模板特化/RAII/异常穿层/STL map/lambda/unique_ptr | 75,288B | 7/7 PASS |
| ObjC | category/protocol/block/multi-block/hex 转换 | 88,360B | 5/5 PASS |
| ObjC++ | C++ 模板持 ObjC 对象/unique_ptr 跨语言/异常/lambda 混合捕获 | 90,656B | 5/5 PASS |

编译:
```bash
CL=src/build/bin/clang++
# C (as C++)
$CL -O2 tests/test_c.cpp tiny_aes.c -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla
# C++
$CL -O2 tests/test_cpp.cpp tiny_aes.c -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla
# ObjC (通过 C wrapper)
$CL -O2 -fobjc-arc -framework Foundation tests/test_objc.m tests/wbaes_c_wrapper.cpp \
    -I. -lc++ -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla
# ObjC++
$CL -O2 -fobjc-arc -framework Foundation tests/test_objcpp.mm \
    -I. -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla
```

注意:
- C wrapper (`wbaes_c_wrapper.cpp`) 是 ObjC/.m 集成的标准方式 (纯 C ABI)
- `WBAESTables` 704KB 不宜放栈上 — 用 static/堆
- in-place encrypt/decrypt (`encrypt(d, d)`) 语义正确但建议非原地 (避免 -O2 别名重排)
- 多 WBAES 实例时 half_b 为全局 (后 init 覆盖先 init) — 多实例需 per-instance half_b

### 5.14 第二层测试矩阵（冷门/高级语法）

| 语言 | 第二层语法覆盖 | 全 pass+MIR | 语义 |
|---|---|---|---|
| C v2 | `_Generic` 泛型宏 / `setjmp`+`longjmp`+信号处理 / 计算间接 goto / 嵌套命名 union / 位反转技巧 / `__sync` 原子 / 二维函数指针矩阵 | 70,016B | 8/8 PASS |
| C++ v2 | C++20 concepts / fold expression / if-constexpr / structured binding / std::variant+visit / std::optional / CTAD / string_view / constexpr static_assert | 69,792B | 10/10 PASS |
| ObjC v2 | method swizzling (`method_exchangeImplementations`) / associated object (`objc_setAssociatedObject`) / dynamic method resolution (`resolveInstanceMethod:`) / NSInvocation / `objc_msgSend` 直调 | 89,808B | 7/7 PASS |
| ObjC++ v2 | C++ virtual + ObjC 桥 / variant 持 NSData* / C++ RAII 桥 ObjC ARC / ObjC block 存 C++ std::function (类型擦除) / C++ 模板持 ObjC 类 | 91,104B | 5/5 PASS |

已知限制记录:
- method swizzling 的 `method_exchangeImplementations` 交换后, swizzled 方法里应调
  交换后的 selector (非原 selector) — 否则无限递归
- NSInvocation 对含 C++ ivar 的 ObjC 类有 SIGBUS 风险 — 通过委托转发绕过
- `std::optional<T[]>` 不合法 (C++ 不允许 optional 持 C 数组) — 用 variant 模拟
- C++ 匿名 struct 在 union 内不可用成员访问 (C++17) — 需命名
- C11 `_Atomic` 与 C++ 不兼容 — C++ 用 `std::atomic`, C 用 `__sync` builtin

## 5.15 JSON 策略文件（无源码标记开启 pass）

**痛点**: `__attribute__((annotate("...")))` 需要改源码 — 对 Dart FFI/Unity IL2CPP/
第三方库/混淆源码不友好。

**方案**: `-mllvm -policy-file=xxx.json` — 从 JSON 文件读取 pass 列表和目标函数，
按 mangled/demangled/子串匹配选择函数。源码零修改。

```json
{
    "passes": ["alias", "gvenc", "indcall", "indbr", "mba", "sub", "bcf", "fla"],
    "targets_mangled": ["__ZN4WBAES7encryptEPKhPh", "__ZN4WBAES8decryptEPKhPh"]
}
```

```bash
CL=src/build/bin/clang++
$CL -O2 source.cpp -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla \
    -mllvm -policy-file=policy.json
```

实现: Pipeline.cpp 加 `-mllvm -policy-file` cl::opt → Utils.cpp 加
`loadPolicyFile()` (轻量 JSON 数组提取, 无外部依赖) → 每个 pass 的
`readAnnotate` 检查旁加 `readPolicyMatch(F) && policyHasPass(cmd_name)`。
支持 mangled/demangled/子串三种目标匹配。

## 5.16 Dart/Flutter/Unity3D 集成

白盒核心通过 **C wrapper dylib** (`libwbaes.dylib`) 暴露 C ABI，
Dart FFI 和 Unity C# P/Invoke 通过同一 dylib 调用：

```
┌──────────┐   FFI/P-Invoke   ┌────────────────┐    C++ MIR    ┌────────┐
│ Dart/C#  │ ───────────────→ │ wbaes_c_wrapper │ ────────────→ │ 白盒核心│
│ Flutter  │ ←─────────────── │ (C ABI)         │ ←──────────── │ (混淆)  │
│ Unity3D  │                  └────────────────┘               └────────┘
└──────────┘
```

构建 dylib:
```bash
CL=src/build/bin/clang++
$CL -O2 -c demo_wbaes_nopol.cpp \
    -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla \
    -mllvm -policy-file=tests/policy_allpass.json -o nopol.o
$CL -O2 -c tiny_aes.c -o ta.o
$CL -O2 -c tests/wbaes_c_wrapper.cpp -o wc.o
$CL -dynamiclib -framework Foundation nopol.o ta.o wc.o -o libwbaes.dylib
```

测试文件:
- `tests/test_dart.dart` — Dart FFI (类/泛型/async/Stream/extension/mixin/工厂)
- `tests/UnityWBAES.cs` — Unity3D C# (P/Invoke/单例/IDisposable/泛型容器/扩展方法)

运行 (需 dart/Unity 环境):
```bash
dart run tests/test_dart.dart           # Dart FFI
# Unity: libwbaes.dylib → Assets/Plugins/, UnityWBAES.cs 挂到场景
```

dylib 验证 (python ctypes / C dlopen 均可):
```c
// test_dylib.c — dlsym + roundtrip
void *h = wbaes_create();
wbaes_encrypt(h, pt, ct);
wbaes_decrypt(h, ct, rt);
// roundtrip PASS ✓
```

## 5.17 iOS 真机测试（全语言 × 函数切割 × JSON 策略）

iPhone 13 (arm64e, iOS 26.5.2) 真机测试，全部通过：

| 语言 | 测试内容 | 全 pass+MIR 切割 | 结果 |
|---|---|---|---|
| C | _Generic/setjmp+signal/计算goto/嵌套union/位反转/原子/函数指针矩阵 | ✓ | **8/8 PASS** |
| ObjC | category/protocol/block/multi-block/map-table | ✓ | **6/6 PASS** |
| ObjC++ | C++ virtual+ObjC 桥/variant/RAII/block 存 std::function/模板持 ObjC | ✓ | **5/5 PASS** |

编译:
```bash
CL=src/build/bin/clang++
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
$CL -arch arm64 -isysroot $SDK -target arm64-apple-ios13.0.0 \
    -O2 -c -DWBAES_NO_MAIN demo_wbaes_nopol.cpp \
    -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla \
    -mllvm -policy-file=tests/policy_allpass.json -o ios_wb.o
```

### iOS 反调试修复（关键教训）

`xcrun devicectl device process launch` 通过 debugserver 启动 →
内核为进程置 `P_TRACED` → `debugger_present()` 返回 true →
S 盒毒化触发 → **表全错 → 输出垃圾 → 崩溃**。

修复：反调试检测到调试器后**不毒化表**，只置标志位。
真正防护由回环自检（encrypt 后 decrypt 比对）+ 轮级双算（DFA 拦截）承担。
用户态反调试无法对抗内核级调试器 — 这是所有用户态反调试的极限。

### 5.18 iOS UI 测试（屏幕可视化验证）

之前的 console 版在 iPhone 上无 UI → SpringBoard 闪退。
改为 UIKit 版（黑色背景 + 绿色等宽字体显示测试结果）：

| App | 测试内容 | bundle ID |
|---|---|---|
| `wb_c_ui` | C 全语法 (_Generic/setjmp/goto/union/位反转/原子/fn-ptr) | `JMD2JV9294.com.polaris.wbaes.cui` |
| `wb_objcpp_ui` | C++ 模板/STL/virtual/lambda + ObjC 混合 | `JMD2JV9294.com.polaris.wbaes.objcppui` |

编译:
```bash
# 编译 .o (JSON 策略 + 全 pass + MIR)
$CL -arch arm64 -isysroot $SDK -target arm64-apple-ios13.0.0 \
    -O2 -fobjc-arc -c -I. -Itests tests/test_c_ui.mm \
    -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla \
    -mllvm -policy-file=tests/policy_allpass.json -o test_c_ui.o

# 链接 (直接 ld — Polaris clang 的 iOS framework 路径有 bug)
LD=$(xcrun -sdk iphoneos -f ld)
$LD -arch arm64 -syslibroot $SDK -e _main -o app/binary test_c_ui.o \
    -framework UIKit -framework Foundation -lc++ -lobjc -lSystem

# 打包 .app → 签名 → 部署
```

### 5.19 第三层测试矩阵（多线程/并发/复杂 C++）

| 语言 | 第三层语法覆盖 | mac | iOS 真机 |
|---|---|---|---|
| C v3 | pthread 4 线程并发加解密 / 递归链式 enc³→dec³ / qsort 密文排序 / pipeline enc→dec→enc→dec→enc / 1000 块 stress / 边界值 (全零/全FF/单bit) | 6/6 PASS | 6/6 PASS |
| C++ v3 | std::thread 4×100 并发 / ThreadSafeWBAES mutex / CRTP 多层继承 / RAII 链 / move semantics / operator 链式调用 / shared_ptr | 6/6 PASS | 6/6 PASS |

发现并修复的问题:
- **多实例全局仿射覆盖**: 多个 WBAES 实例的 init_tables 各自覆盖 g_sbox_aff/g_out_aff 等全局
  → 修复: 仿射只生成一次 (`g_affine_generated` flag), 多实例共享
- **lambda 栈溢出**: viewDidLoad 局部 WBAES (704KB) → 栈溢出 → 改 static + 指针捕获
- **ThreadSafeWBAES**: mutex 保护的线程安全封装, 并发加密解密正确

### 5.20 第四/五层测试矩阵（深层语法 + 编译期元编程）

| 语言 | 语法覆盖 | 全 pass+MIR | 语义 |
|---|---|---|---|
| C v4 | VTable 多态模拟 / 内存池 / 环形缓冲区 / 大端序列化 / 位分片 | 65,032B | 5/5 PASS |
| C++ v4 | SFINAE / NTTP / Tag Dispatch / 自定义迭代器 / Pimpl / Observer | 单 TU | 6/6 PASS |
| C++ v5 | constexpr MC 表 / 模板递归 Chain<N> / 编译期状态机 / NTTP static_assert | 单 TU | 5/5 PASS |
| C v5 | 宏函数生成代码 / _Alignas / 枚举位标志 / FNV 完整性 / 序列化结构体 | 单 TU | 6/6 PASS |

关键发现:
- **多 WBAES 实例全局仿射覆盖**: 多实例 init_tables 各自覆盖 g_sbox_aff/g_out_aff —
  后续实例的 encrypt 出口剥离使用错误仿射 → 输出错。
  修复: 仿射只生成一次 (`g_affine_generated` flag)，多实例共享
- **lambda 栈溢出**: viewDidLoad 局部 WBAES (704KB) → 栈溢出 → static + 指针捕获
- **测试期望值错误**: 换密钥后 test_ct 须同步更新（旧 test_ct 是旧密钥的密文）

### 5.21 中大型项目风格测试矩阵（v6/v7，多文件 + 深层数据结构）

模拟真实中大型 C/C++ 项目结构（多 .c/.h 文件、深层数据结构、并发、异常安全），全部在 macOS + iPhone 13 真机（全 8 pass 混淆）下验证。

**C v6 — 多文件项目（tests/c_project/ 4 模块 + 主测试）5/5 PASS**

| 测试 | 场景 | 语法覆盖 |
|---|---|---|
| hashtable-enc | 加密值入哈希表 → 取出 → 解密 → 覆盖/删除 | 独立 .c/.h 模块、链地址法、djb2 hash |
| bignum-xor | 256-bit 大整数 XOR 域运算 × 白盒加解密往返 | 32B 双块处理、大端序列化 |
| base64-roundtrip | 加密 → Base64 编码 → 解码 → 解密 | 非对齐长度 (20B→28 chars)、padding |
| crc32-integrity | 加密前后 CRC32 变化 + 解密后 CRC 还原 | 位反转 CRC、完整性校验 |
| dlist-enc-crc | 双向链表节点加密 + CRC 校验 + 正/反向遍历 | 动态节点、正反向指针 |

**C++ v6 — STL 深层 + 设计模式 + 并发 6/6 PASS**

| 测试 | 场景 | C++ 特性 |
|---|---|---|
| stl-nested-map-vec | map<string, vector<array<uint8_t,16>>> 加密金库 | 嵌套 STL 容器 |
| smartptr-chain | enc→enc→dec→dec 管线 = identity + weak_ptr 观测 | shared_ptr/weak_ptr 生命周期 |
| factory-registry | 工厂注册 Encrypt/Decrypt maker → create → 未知 id 返回 nullptr | 单例 + std::function 注册表 |
| threadpool-8t | 8 线程并发加密 200 块 → 全部解密验证 | mutex/cv/atomic、优雅 join |
| exception-raii | 中途 throw → 栈展开 → 加密状态可还原 | RAII guard、异常安全 |
| variant-visit | variant<Enc*, Dec*, int> + std::visit 分派 | C++17 variant |

**C v7 — 深层 C 结构 5/5 PASS**

| 测试 | 场景 | 语法覆盖 |
|---|---|---|
| fsm-protocol | 0xAA 帧头协议 FSM 解析密文帧 → 解密验证 | 函数指针状态机、帧解析 |
| matrix4x4 | 4×16 矩阵按行加密/解密扫描 + 密文态校验和 | 行连续 16B=1 AES 块 |
| rd-parser | 递归下降解析 enc(dec(42)) 嵌套表达式 | 递归解析器、运算即加解密 |
| bitmap-pages | 128 页位图标记 + 位图整体加密 + 页数据加密 | 位操作宏、BM_SET/BM_GET |
| heap-enc | 二叉堆按 prio pop → 解密后数据顺序正确 | 上滤/下滤、加密节点交换 |

**构建注意**（本轮排障沉淀）:
- C/C++ 混链: c_project/*.c 须按 `-x c` 单独编译（C 符号不 mangle），test 用 `-x c++`，`.o` 前加 `-x none` 切回
- zsh 不做变量 word-split: `-mllvm -passes=...` 必须写字面值，不能存进 `$VAR` 传
- WBAES::encrypt 单块 16B: 多块数据须逐块调用（bignum 32B 双块教训）
- extern "C" 包裹 C 头文件（test 为 C++ TU 时）
- devicectl `--console` 桥接 stdout 并等待退出（抓真机测试输出）

### 5.22 运行时防护层 v3（P0+P1：环境自保四件套）

全部复用 `g_key_tampered` 毒化管道 — 任一防护命中 → seed 污染 → 表失真 → 输出乱码，无语义反馈，攻击者无法定位命中层。

| 层 | 机制 | 触发条件 | 响应 |
|---|---|---|---|
| 反调试 v3 | `sysctl KERN_PROC` 查 `P_TRACED` + frida 镜像名扫描 + 127.0.0.1:27042 端口探测，init/encrypt/decrypt 三点交叉 | 调试器 attach 或 frida 注入 | **延迟毒化**：随机 60-300s 后才置污染位（攻击者短期误判绕过成功）|
| 反单步时间侧信道 | encrypt/decrypt 入出口 `mach_absolute_time` 差值 | 单步/trace 拉长 >100ms（正常 <1ms）| **立即毒化**（时间异常即攻击证据）|
| __TEXT 自校验 | init 时对白盒核心 8 页（32KB）建 FNV 基线，调用轮转抽查 1 页 | Frida inline hook / 二进制 patch | 立即毒化 |
| 仿射表用后即焚 | init 完成后 volatile 清零 `g_sbox_aff`/`g_inv_aff`/`g_aff[9]`/`daff_*` | —（常态执行）| 内存 dump 拿不到轮间编码 → BGE 剥离链条断；运行时仅 `g_out_aff`（出口剥离）存活 |

实现位置：`demo_wbaes_noasm.cpp`（`#if defined(__APPLE__)` 块）。

**历史坑**：
- 首版反调试（立即毒化）被 devicectl 启动时的 P_TRACED 误触发 → 全套闪退 → v3 改延迟毒化解决
- TEXT 自校验首版用单页基线比全部页 → 必然失配 → 改 8 页独立基线 + 轮转抽查
- CommandLineTools SDK 27.2 的 tbd 文件含新架构语法（arm64e.x1-macos），Polaris clang 不识别 → 链接用 `-isysroot Xcode16.4.../MacOSX15.5.sdk`

**验证状态**：macOS plain + 全 10-pass 混淆，C v6/v7、C++ v6 全部 ALL PASS。iOS 真机重编完成（`/tmp/wbaes_ios_sec/`），装机因开发证书 2026-11-03 到期暂阻，续期后签名即装。

### 5.23 P2 设备绑定 + 密钥三路分散（客户端-only 密钥防护）

**核心**: 工作密钥 = 主分片 ⊕ 设备因子 → 二进制静态无完整密钥、无可用分片组合。

```
因子 (32B) = FNV挤压( halfA ⊕ halfB ⊕ UUID派生 ⊕ halfS )
  halfA: Keychain (首次随机, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
  halfB: NSUserDefaults 伪装项 "last_metric_ts_seq" (首次随机)
  UUID:  identifierForVendor (iOS) / hostname (macOS) FNV 双域 16B
  halfS: SEP EC256 签名前 16B (仅 iOS; 首次签名→缓存 Keychain, 跨会话稳定)
```

- 接入点: `wbaes_key.h key_byte(i)` — `kb = KBLK⊕CBLK ^ devbind_byte(i)`
- 换设备 → 因子不同 → 表重建后密钥不同 → **单设备破解不可复制**
- 删 app 重装: Keychain 存活 (iOS) → 因子稳定; NSUD 丢失自动重建
- `WBAES_NO_DEVBIND` 编译开关 → 纯分片模式 (密钥 d796fc6e..., openssl 互操作/标准向量)
- devbind 失败 (Keychain 全挂) → 静默回退纯分片 (可用性优先)
- 实现: `tests/devbind.mm` (Foundation/Security, macOS+iOS 通用)

**坑**: SEP 签名含随机数每次不同 → 直接用会导致因子漂移 (表每次 init 重建) → 必须缓存 Keychain 后读回。

**验证**: P2 版 macOS 三套件 (全 10-pass 混淆) ALL PASS ×2 (因子稳定); iOS 二进制静态无明文密钥; 互操作模式 ALL PASS。

**P2 后攻击面**: 静态提取失效 / 二进制拷贝失效 / 动态调试三重拦截 / dump 无仿射无因子 — 剩余仅 root+无限时间逐设备逆向 (客户端天花板)。

### 5.24 P3 DFA 故障注入自检测试（防护有效性闭环验证）

新增 `tests/test_dfa.cpp` — **主动验证 DFA 防护**（此前 2000 项采样是开发期内部脚本，现为可复跑回归测试）：

| 测试 | 故障注入 | 预期防护 | 结果 |
|---|---|---|---|
| baseline roundtrip | —（无故障基线）| enc→dec 还原 | PASS |
| table-fault WB | t1.WB 全 9 轮 × 全 kk/j × 值域 0..15 全翻转 | 轮级双算失配 → enc 输出垃圾 + dec 不还原 | PASS (differs=1, not_plain=1) |
| table-fault TF | t1.TF 全表**非均匀掩码**翻转（每项独立）| 末轮双算失配 → 同上 | PASS |
| decoy-poison | t1.DECOY[0..1][*] 全翻 | 陷阱抽查命中 → 全局毒化 → 后续输出全垃圾 | PASS (poisoned=1) |

**P3-1 新增第三轨**: enc_core 轮间状态校验链（FNV(s1⊕s2) 逐轮滚动 + 会话 kk 序混淆）—
攻击者须同时改 s1/s2/链值三处内存（多点同步故障）才能骗过轮级双算。

**DFA 测试排障记录**（重要教训）:
1. **WB fault 首次 FAIL**: 翻转 WB[0][0][0][x] 不生效 — WB_PLAN 乱序（物理轮 ≠ 运行轮），
   注入必须覆盖 9 轮 × 全 kk/j × 值域（plan 全空间）
2. **TF fault 全表等量翻转不生效**: 末轮每列 XOR 合并 4 表项 —
   等量翻转 (4×FF) **自抵消**，n1 恒不变！必须 per-item 非均匀掩码。
   （诊断过程：n1 恒定 + dec 输出变化 → XOR 合并代数 → 自抵消结论）
3. **decoy 命中率**: 随机抽查 di∈0..15, dz∈0..255 — 只翻 DECOY[0][*] 时 32 次 encrypt
   P(命中)≈87% 仍可能 0 命中 — 翻 DECOY[0..1][*] + 64 次覆盖到 P≈99.96%
4. **Keychain 首访弹窗**: 命令行进程首次 Keychain 访问弹安全授权框 → 测试"卡死"假象
   （等用户点允许）— DFA 测试用 `-DWBAES_NO_DEVBIND` 绕开；app 内无此问题

**验证**: DFA 自检 + C v6/C++ v6/C v7 全套（10-pass 混淆 + devbind）全 ALL PASS。

**导出**: `macos/wbaes_dfa_selftest`（可独立复跑的防护自检二进制）。

### 5.25 P3 深化（第三轨对称 + fault 时序混淆）

**dec_core 第三轨补齐**: 解密方向与 enc_core 对称加校验链（逆轮状态滚动 FNV + 末逆轮总检）—
DFA 也可攻击解密路径（fault dec 收集 (ct, pt') 差分），现在两条 core 都有链。

**fault 时序混淆（失配空转）**: enc_core 轮级失配后不立即 return —
继续 0..7 轮随机"空转"（真实查表 WB[plan]，值弃用）再返回垃圾 —
攻击者无法从**时序差**定位 fault 命中的轮号，防 fault 定位扫描。

**会话化列重排评估结论**: ShiftRows 查表下标 (j+kk)%4 依赖物理布局，会话化列置换需
每会话重生成表（init 秒级→不可行）— 记录为不采纳方向。

**验证**: DFA 自检 4/4 + C v6/C++ v6/C v7（10-pass 混淆 + devbind + P3 全部）ALL PASS；
iOS P3 重编 3 个 UI 二进制完成（装机仍待证书续期）。

### 5.26 HSV 虚拟机进热路径（2026-11-17）

导出的这一代（`wbaes_vm_*`）里有一段**真的在跑**的 HSV 字节码：每轮、每个状态字节的
表偏移由 VM 算，C++ 侧不再自己推地址。位置与边界见 `WB-DESIGN-V2.md` §5，
为什么整轮不能搬进 VM 见 `research/hsvm/reports/S5-nativevm/v15-vm-in-wbaes.md`。

**字节码做什么**（`wbaes_vm.cpp`，ISA v2、43 条指令 / 344 字节 / 16 寄存器 / 4 KiB 内存）：

```
输入  arg = (dir << 8) | (round << 4) | i
fam   = 调度块字节 [dir*16 + round]                ← Tld（ISA v2 的 0x10）
off   = base[dir] + round*round_stride[dir] + (i>>2)*col_stride
        + lane_stride(fam, i&3)
输出  St 回 VM 内存 4*i，并作为 r0 返回
```

`base / round_stride / col_stride / lane_stride / pair_stride` 全部由生成端写进表尾调度块
（偏移 32/36、40/44、48、52、56），VM 用 Tld 逐个读出来——字节码里没有 69 MB 布局的
任何常量（`tests/test_vm_offsets.cpp` 用非本机布局字验证这一点）。
所以调度块被改一个字节，偏移就跟着错，而不是"校验发现后照旧用常量"。

**编译接线**：只有 `wbaes_vm.cpp` 走 `-mllvm -passes=hsvm`，pass 把 `@hsvm_bytecode`
降低成 `@hsvm_entry` 的原生代码（一条指令一个基本块、直接分支，没有 opcode 取指、
没有解释器分发循环）；demo/bench 两个 TU 保持原来的 pass 列表。

```bash
W=$PWD
# 1) 生成表（含调度块布局字），换钥后必做
clang++ -O2 -std=c++17 -I$W gen_hybrid.cpp -o gen_hybrid && ./gen_hybrid hy_table.bin
# 2) 字节码 TU：只加 hsvm
clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. -I$W \
        -mllvm -passes=hsvm -c wbaes_vm.cpp -o wbaes_vm.o
# 3) demo（clean / max 两档）
clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. -I$W \
        demo_wbaes.cpp hy_tab.S wbaes_vm.o -o wbaes_vm_clean
clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. -I$W \
        demo_wbaes.cpp hy_tab.S wbaes_vm.o \
        -mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla -o wbaes_vm_max
```

**V1–V6（判据见 `VM-REQUIREMENT.md`）**

| 判据 | 命令 | 结果 |
|---|---|---|
| V1 产物里有 VM | `nm wbaes_vm_clean \| grep hsvm` | `_hsvm_bytecode` `_hsvm_entry` `_hsvm_table` `_hsvm_table_len` |
| | `otool -s __DATA __hsvm wbaes_vm_clean` | 43 条 8 字节指令，首条 `0x01 0x08 …`，其中 6 条是 `0x10`（tld） |
| | `otool -tv` 里 `_hsvm_entry` 的 `br x*` 计数 | **0**（172 条指令，全是直接 `b`/`cbz`/`cbnz`，无分发循环） |
| V2 VM 真被执行 | `-DWBAES_VM_SCHEDTEST` | 翻转调度块第 48 字节（列步长低字节；不在族校验里、不在抽样封印的采样点上）→ 密文 `29d00ce8…` → `5d138252…`，恢复后回到 `29d00ce8…` |
| V3 函数不变 | 旧钥 `755e…` 下混合 + 四个强制族各生成一次 | 五次密文全部 `abe296eea2625f251ba57ed0b408272c` |
| V4 性能 | `bench_wbaes 3000`，同一张表 | 关 VM `4.11 / 4.83 µs`，开 VM `10.56 / 11.33 µs`（见下） |
| V5 双算不退化 | `-DWBAES_DFA_SELFTEST` | 三次三份不同垃圾，`vector-match: FAIL` |
| V6 自检 | `gen_hybrid` 退出码 + demo | 生成端 0（`table-check PASS` / `seal-check PASS`，未走 `return 8/9`）；demo `roundtrip: PASS` |

**V4 的成本，以及它为什么不是免费的**：`hy_mc_round` 的每个表地址都来自 VM，
一个块（一次加密、一次解密）要 **288 次 `hsvm_entry`**（16 个偏移 × 9 轮 × 2 方向）。
单次调用 **40.5 ns**（`hsvm_entry` 微基准），其中大部分是 pass 每次调用都要清零
4 KiB VM 内存（降低后的入口里是 `bzero(…, 0x1000)`）加 16 个寄存器初值，字节码本身只占
十几纳秒。所以：

```
加密 4.11 → 10.56 µs（×2.6）   解密 4.83 → 11.33 µs（×2.3）
```

这就是把偏移计算搬进 VM 的实价：同一个数量级以内、但确实慢一倍多。
ISA 只允许 `r0` 一个出口（没有"写宿主内存"的 opcode，`Tst` 在
`v15-vm-in-wbaes.md` 里只是提案），所以 16 个偏移只能 16 次调用；
若以后加 `Tst` 或让 `hsvm_entry` 返回打包值，这一项可以按倍数降下来。

**边界（不要夸大）**：进 VM 的是"轮控制流 + 表偏移"，不是表数据本身。
攻击者仍然静态读那 69 MB 表；VM 在这里买到的是"热路径确实由字节码驱动"，
而反编译读表的人仍会看到 `hy_mc_round` 的表形状分派。

### 5.27 dl5：跨 lane 非线性重编码（2026-11-18）

dl4 的两条攻击（`attacks/bge_attack.py` 17 s、`attacks/dca_attack.py` 0.2 s）都成功，
原因写在 `WB-DESIGN-V2.md` §十一：组合是 XOR、每条 lane 一个逐元素双射 ⇒ 64K 解码表必然是
`D0[a]^D1[b]`，逐 lane 的逆一定可分；轮边界又是 256 项表，下标恰为 `MC·S(pt^rk0)`。
dl5 改的就是这两处，**不改**函数（密文逐字节一致）、VM、DFA 双算、封印、四族调度。

**构造**（每列 798720 B，`wbaes_hybrid.h` 里的 `HY_COL`）：

| 区段 | 字节 | 内容 |
|---|---|---|
| `[0,4096)` | 4 KiB | F1/F3 四条 32 位 lane 表 / F2 十六张系数表 / F0 前置两张 16 位索引表（512 KiB，与其它族区段重叠但互不读取） |
| `[4096,528384)` | 512 KiB | F1/F2/F3 八张 64K 成对解码表 |
| `[528384,536576)` | 8 KiB | 32 位重编码：12 张正向 S 表 + 12 张逆向 S 表 + 12 个每轮常量 |
| `[536576,798720)` | 256 KiB | 四张 64K **两字节**边界表 |

1. **成对解码表带上输出双射**：`Q[a][b] = Z(D0[a] ^ D1[b])`，`Z` 每 (row,p) 随机。
   表不再是秩 1 张量：一行 + 一列拟合不出它（实测 122400 个非轴向项里只复现 974 个 = 0.80%，
   随机表期望 0.39%）。
2. **边界表改成两字节下标**：`out = P[Zl⁻¹(u) ^ Zr⁻¹(v) ^ rk]`，`u`、`v` 是两条成对解码的输出。
   `Zl⁻¹`/`Zr⁻¹` 不作为独立数组存在，只存在于这张 64K 表的值里。
3. **32 位非线性重编码**：一列的四个输出字节当作一个 32 位字，过三轮
   （异或每轮常量 → 逐字节随机双射 → 固定 4×4 MDS）。MDS 是循环矩阵 `(1,4,3,7)`，逆为
   `(11,11,9,8)`；生成端 `spn-mds: PASS` 校验两者互逆且所有方子式非零。
   轮边界处由 `hy_rec_undo()` 用存的逆向 S 表 + `hy_mds_inv()` 还原。
4. **F0 也改了**：旧的两张 256 项逆表（`Qi`，读表即得 `Q` 的逆）删掉，改为共用同一张两字节边界表。

**为什么逆不能拆成 per-lane 数组**：`R` 的逆是
`S1⁻¹ ∘ MDS⁻¹ ∘ S2⁻¹ ∘ MDS⁻¹ ∘ S3⁻¹ ∘ MDS⁻¹` —— 每个 `MDS⁻¹` 都混一列的全部四个字节，
所以逆不是四个独立的 256 项映射；而 `R` 的逆也从不落盘（生成端只写正向 S 与逆向 S，
从不写复合逆）。工程上还有一个硬约束：状态在每个轮边界要按**单字节**消费，
所以 32 位非线性只能放在“这一轮的输出、下一轮开头立刻还原”的位置——把它放在成对解码与边界之间
会毁掉恢复 `x_r ⊕ y_r` 所需的信息（4 字节混过之后，2 字节表无法还原单行）。

**闸门（本机实跑，key `46f6abe5…`，产物 `wbaes_nl_clean`）**

| 闸门 | 命令 | 结果 |
|---|---|---|
| G1 BGE 失效 | `python3 attacks/bge_attack.py` | 第 1 步 974/122400（0.80%）非轴向拟合 → `incomplete (0/16 bytes)`，rc=1 |
| G2 DCA 失效 | `python3 attacks/dca_attack.py --traces …` | 6 个 (tag, half) 组合全 0 候选 → `0/16 bytes`，rc=1；下标是成对和的**双射像**而非其本身（`index == pair sum 0/8`） |
| G3 密文一致 | 混合 + `--fam 0/1/2/3` | 五次 `80aadc09777696c9d492a7e53b3b15b0`（旧钥 `07d9…` 下五次 `29d00ce827afdb377671f07402cda1f5`） |
| G4 V1–V6 | 见下 | 全过 |
| G5 体积/耗时 | 表 69,206,080 → **70,090,816** B（+1.28%）；`bench_wbaes 3000` 加密 10.02 → **22.29 µs**、解密 10.66 → **22.21 µs**（同钥同 VM 配置，×2.2/×2.1） |
| G6 自检 | `gen_hybrid`、demo、`tests/test_vm_offsets` | `table-check PASS` / `seal-check PASS`（未走 return 9）、`roundtrip: PASS`、`vm-offsets: PASS` |

**V1–V6（同一代）**

| 判据 | 命令 | 结果 |
|---|---|---|
| V1 产物里有 VM | `nm wbaes_nl_clean \| grep hsvm` | `_hsvm_bytecode` `_hsvm_entry` `_hsvm_table` `_hsvm_table_len` |
| | `otool -s __DATA __hsvm` | 43 条 8 字节指令 / 344 B，其中 6 条 `0x10`（tld） |
| | `_hsvm_entry` 反汇编 | 172 条指令，`br`（间接跳转）**0** 条，无分发循环 |
| V2 VM 真被执行 | `-DWBAES_VM_SCHEDTEST` | 翻调度块第 48 字节 → 密文 `1268c986…`，恢复 → `80aadc09…` |
| V3 函数不变 | 五个生成（混合 + 四族） | 全部 `80aadc09777696c9d492a7e53b3b15b0` |
| V4 性能 | 见 G5 | 一个数量级以内（×2.2） |
| V5 双算不退化 | `-DWBAES_DFA_SELFTEST` | 密文 `4d20093c…`、回环 `8591731d…`，`vector-match: FAIL` |
| V6 自检 | 生成端 / demo / VM 偏移 | 全 PASS（见 G6） |

**攻击脚本的改动（没有削弱闸门）**：`wblib.py` 的表几何常量改成 dl5 布局，`mc_round`/`encrypt`
照 `hy_mc_round` 的新尾巴重写（多记 12 次重编码读 + 2 字节边界读），新增 `hy_scatter_inv()`
（16 位 Feistel 求逆，用来从地址精确还原 64K 表的逻辑下标）。`dca_attack.py` 的实验 B 改为
“还原 2 字节下标 → 两个半字节各跑一遍原来的 4 字节 MITM”，并打印测得的结构事实；
`bge_attack.py` 的拟合逻辑一个字没改，只把“轴向项不算数”讲清楚。
两条攻击的**判定条件没变**（要么出 16/16 字节密钥、要么失败），难度也没降——
它们现在读的是新形状，仍然拿不到密钥。

**导出**：`exported-binaries/wbaes-challenge/macos/wbaes_nl_clean` /
`wbaes_nl_max`（`strip -S` 后各 70,707,000 B），sha256 见该目录 `sha256.txt`。

**已知上限（不要夸大）**：(1) 重编码是**状态编码**，不是代数屏障——把 `__hytab` 解掩后
读 12 张逆向 S 表 + 已知 MDS 就能求逆，它买到的是“轮边界内存里没有单字节明文域状态”
和单字节故障扩散成 4 字节；(2) 成对表的 `Z` 让 BGE 第一步失效，但 `Q = Z∘(D0⊕D1)` 是隐藏位移
问题，属于研究级攻击，本次未实现、未测；(3) 边界下标虽被 `Z` 挡住，但实测它仍是成对和的**函数**
（0 冲突），所以要打只能靠“未知双射一致性”统计——需要约 2^12 条轨迹，本次未实现；
(4) F0 前置 512 KiB 与其它族区段重叠（互不读取，但静态读者可能误判）。

### 5.28 VM 层 P0：一次调用算完整张偏移表，宿主从 VM 内存读回（2026-11-18）

§5.26 那版 VM（43 条指令）**一次调用只算一个偏移**，唯一出口是 `r0`，所以一个块要 288 次调用
（16 偏移 × 9 轮 × 2 方向），每块为此多付 ≈6 µs。这一节把 `WB-DESIGN-V2.md` §13 的两条 P0 一起做掉：

| P0 | 做法 | 结果 |
|---|---|---|
| P0-a：偏移只算一次 | 字节码自己走 2 方向 × 9 轮 × 16 字节，`St` 把 288 个偏移写进 VM 内存；宿主算一次就缓存 | 每块 288 次 → **0** 次；整张表 **1 次调用 / 0.86 µs**，在第一次加解密时付 |
| P0-b：把值取出来 | pass 支持 `@hsvm_mem`：模块里定义了 `unsigned char hsvm_mem[4096]` 就用它当 VM 内存面（没有则退回原来的 alloca） | 不需要 ISA v3 / `Tst`，ISA 仍是 v2，解释器/oracle 未动 |

**为什么不是“把九轮搬进字节码”**：偏移只依赖调度块和布局字，与明文/密钥无关，是**每构建固定**的；
把九轮做成 VM 循环一个偏移也省不下来，反而把 69 MB 数据面耦合进字节码。所以这里落的是
“一次算完 + 宿主缓存”，§13 的两条 P0 合成一条实现，理由写在这里而不是留给读者猜。

**字节码**（`wbaes_vm.cpp`，ISA v2、61 条指令 / 488 字节 / 16 寄存器 / 4 KiB 内存，6 条 `Tld`、1 条 `St`）：

```
for dir in 0,1:                                     # 0 = 加密, 1 = 解密
  for round in 0..8:
    fam = Tld[dir*16 + (round & 12)] 的第 (round & 3) 个字节     ← 调度块族字节
    acc = Tld[32 + 4*dir] + round * Tld[40 + 4*dir]              ← base + round*stride
    for i in 0..15:
      off = acc + (i>>2) * Tld[48]                                ← 列槽
             + (fam == 0 ? ((i&3) >= 2 ? Tld[56] : 0)             ← F0: 第二张 pair 表
                          : (i&3) * Tld[52])                      ← F1/F2/F3: 每 lane 一张
      St Mem[4 * (dir*144 + round*16 + i)], off                   ← 写 VM 内存
  r0 = 0, halt                                                    ← 结果不再挤在 r0 里
```

三个循环用 `Brz`/`Jmp` 收尾，1/9/12/16/24 这些常数都由 3/2/0/4 现算（`Sub`/`Shl`），
所以字节码里仍然**没有** 69 MB 布局的任何常量——`tests/test_vm_offsets` 用非本机布局字
（base 1000、col stride 12288…）验证这一点，现在既有逐 (dir,round) 的旧接口，
也有一次取 288 项的 `hy_vm_plan()`，两条路都要和 C 参考逐项相等。

**内存怎么出 VM**（`src/llvm/lib/Transforms/Obfuscation/HSVMLowering.cpp`）：降低时先找
`@hsvm_mem`，类型是 `[4096 x i8]` 且不是常量就把它当内存面，每次调用照样先 `bzero` 4 KiB
（语义与 alloca 版一致）；找不到就退回 alloca。所以 `research/hsvm` 的 28 个 ctest 和
`scripts/verify_vmp_gate.sh` 行为一个字没变（它们不定义这个全局），ISA 文件、`sync_isa.py`、
解释器、oracle 都不用碰。

**计划的生命周期**：`hy_vm_plan()` 把 288 个偏移取回 `hy_vm_off[2][9][16]`（1152 B，
同时检查每项 `<= HY_TOTAL - HY_U32`，越界即判定 VM 故障）；之后每个块只比一次
**调度块快照**（64 B `memcmp`）：一样就用缓存，不一样就重新跑一次 VM。
所以 V2 仍然是真的：改坏调度块第 48 字节 → 快照不等 → 重走 VM → 偏移变 → 密文变。

**实测（同一张表、同一台机器，`bench_wbaes 3000`，3 次运行取最小值）**

| 配置 | 加密 | 解密 |
|---|---|---|
| 关 VM（下界） | 17.23 µs | 16.68 µs |
| 改前：每块 288 次 `hsvm_entry` | 23.34 µs | 23.15 µs |
| 改后：一次调用 + 缓存 | **16.93 µs** | **16.85 µs** |

VM 的固定开销（每块 ≈6 µs）整个消失，开 VM 与关 VM 落在同一档（差值在噪声内）。
单次成本实测：整张表一次调用 **0.86 µs**（288 个偏移），切成 18 次 (dir,round) 调用要
**15.2 µs**——那正是原来每块 288 次调用在付的钱。
（本机当时负载 ≈3.5、`mds_stores` 占 170% CPU，绝对数比 §5.27 记录的 22.29 / 10.02 µs 高，
所以只拿同一台机器、同一张表的前后两行做比较。）

**V1–V6（产物 `wbaes_vm2_clean`，密钥 `4f06…`）**

| 判据 | 命令 | 结果 |
|---|---|---|
| V1 产物里有 VM | `nm wbaes_vm2_clean \| grep hsvm` | `_hsvm_bytecode` `_hsvm_entry` `_hsvm_mem` `_hsvm_table` `_hsvm_table_len` |
| | `otool -s __DATA __hsvm` | 61 条 8 字节指令 / 488 B；6 条 `0x10`(tld)、1 条 `0x0c`(st)、5 `brz`、4 `jmp` |
| | `_hsvm_entry` 反汇编 | 206 条指令，间接 `br x*` **0** 条（无分发循环）；`bzero` 目标 = `_hsvm_mem` |
| V2 VM 真被执行 | `-DWBAES_VM_SCHEDTEST` | 完好 `7672415a…` → 翻第 48 字节 `00ec5944…` → 恢复 `7672415a…` |
| V3 函数不变 | 混合 + `--fam 0/1/2/3` 五次生成 | 五次密文全 `7672415a6313c58518fc95c9cb6922b8` |
| V4 性能 | `bench_wbaes 3000` | 见上表：23.34/23.15 → 16.93/16.85 µs，与关 VM 同档 |
| V5 双算不退化 | `-DWBAES_DFA_SELFTEST` | 密文 `2ec972ad…`、回环 `9583108b…`，`vector-match: FAIL` |
| V6 自检 | `gen_hybrid` / demo / `tests/test_vm_offsets` | 生成端 rc=0（`table-check`/`seal-check` PASS）、`roundtrip: PASS`、`vm-offsets: PASS`（含 288 项批量计划） |

**两条已提交的攻击脚本在新产物上仍然失败**（`4f06…` 这一代，脚本里的已知答案常量已同步到新钥，
判定逻辑一个字没改）：

```
python3 demos/wbaes/attacks/bge_attack.py --binary exported-binaries/wbaes-challenge/macos/wbaes_vm2_clean
  → 0.0076 轴外命中（随机 0.0039）→ 每列 0 个候选 → incomplete (0/16 bytes)      rc=1
python3 demos/wbaes/attacks/dca_attack.py --binary …/wbaes_vm2_clean --traces …/dl4_traces.bin
  → A: 真钥秩 45–245/256；B: 6 个 (tag, half) 组合全 0 候选 → incomplete 0/16   rc=1
```

**代价与边界（不要夸大）**

- VM 不再**每块**执行：每进程（每次换表）执行一次 0.86 µs 的计划计算，之后每块只做 64 B 快照比较。
  “热路径由字节码驱动”在这一代只对**表加载**成立，对每块不再成立——这是用 6 µs/块换来的，
  写在这里而不是留给读者自己发现。`VM-REQUIREMENT.md` 的 V2/V4 注已同步改口径。
- 偏移的**数值**与改前逐位相同（`tests/test_vm_offsets` 与 V3 密文都证明），所以静态读表的人
  看到的地址序列不变；这一代买到的是耗时，不是新的静态屏障。
- 计划缓存是宿主内存里的 1152 B，就在解掩后的表旁边；dump 内存的对手能读到它，
  但那些值本来就能由表尾调度块 + 公开定位公式算出来，所以不算新增泄漏面。
- **这一代仍被 residual 攻击打穿**（与 VM 无关）：`attacks/residual/hs_attack.py` 在
  `wbaes_vm2_clean` 上 3.16 s 取回 `4f065a03…`，`reproduces the shipped ciphertext: YES`。
  表结构和 dl5 一样，换钥不等于换结构；两条 P0 买到的是耗时，不是新的静态屏障。

## 6. 安全性边界（教学版声明）

本实现是 Chow 思路的**简化教学版**，与完整 Chow white-box 差距：

- ✅ 已具备：轮间仿射外部编码（2.5 节）——表数据无裸 AES 轮廓，静态表压缩/
  代数分析第一步失效；表随机化（换密钥 ⇒ 编码矩阵全变 ⇒ 表全变）
- 密钥分片 XOR 存储，二进制中密钥/轮密钥明文序列 0 命中（已验证）
- ⚠️ 编码是 GF(2) 线性仿射，**不抵抗 DFA**（差分故障分析）——抗 DFA 需要非线性
  双射编码 + T-box/混合双射分离 + 内部编码消除网络（Chow 完整版）
- ⚠️ 仿射矩阵由密钥派生且确定性生成：同一密钥每次编译表相同；
  生产版应每次构建注入随机种子

生产化方向：非线性外部编码（每轮 I/O 加可逆非线性 bijection 对）、
T-box/混合双射分离、配合 Polaris MIR 混淆增加逆向成本。
