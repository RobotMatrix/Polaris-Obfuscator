# 每次改动后的基本验证（wbaes）

目的：改完任何东西（生成器、运行时、VM 字节码、攻击脚本、导出流程、文档）之后，
用一条命令确认"基本功能还在、没有静默遗漏"。它**不**回答"强度如何"——强度是另一回事，
闸门写法见 `FINAL-ASSESSMENT.md` §六。

## 一条命令

```sh
cd demos/wbaes
python3 tools/verify_all.py              # 全量：产物 + sha256 + 自检 + openssl + VM
python3 tools/verify_all.py --quick      # 跳过 openssl（约一半时间）
python3 tools/verify_all.py --only f4,nl # 只验指定代
python3 tools/verify_all.py --attacks --research   # 再加攻击脚本冒烟 + research/hsvm ctest
```

退出码 0 = 全过；非 0 会打印 `FAILED: gen/check` 列表。

## 它检查什么（每个已导出的代）

| 检查 | 含义 | 失败通常意味着 |
|---|---|---|
| `exists` | 产物在 `exported-binaries/wbaes-challenge/macos/` | 导出没做 / 路径改了 |
| `size` | 与 `tools/baseline.json` 记录的体积逐字节一致 | 表几何或元数据变了（必须确认是有意改动，然后 `--update-baseline`） |
| `cold start` | 进程启动 + 70 MB 解掩 + 封印校验 + 1 块的耗时，允许比基线慢 25% | 解掩/校验路径变慢，或表变大 |
| `sha256` | 与同目录 `sha256.txt` 一致 | 产物被替换，或 sha256.txt 没更新（两种情况都要查清） |
| `ciphertext` | 自检打印的密文等于该代的期望值 | 生成器/运行时改坏了函数 |
| `self-check` | `vector-match: PASS` | 同上，或自检代码被改动 |
| `openssl` | `openssl -K <该代密钥>` 独立复算同一密文 | 密钥与产物不匹配，或期望值抄错 |
| `vm symbols` | `_hsvm_entry/_hsvm_bytecode/_hsvm_table` 在位 | VM 没被 lowering，或导出时 strip 过度 |
| `no dispatch loop` | `_hsvm_entry` 内无 `br x*` | lowering 退化成解释器 |

## 它刻意不检查什么

```
✗ 每块加解密速度：demo 只跑一块，测不出单块成本（它测的是"启动 + 解掩 + 1 块"= cold start）
  单块数字来自 bench_wbaes，记录在 WB-DESIGN-V2 / FINAL-ASSESSMENT，不在这个门里
✗ 攻击强度：任何"某脚本失败/成功"都不是回归判据
   —— 历史上五个脚本全失败、密钥仍被 1.4 s 拿到；脚本成功也只是那条路径的结论
✓ 强度只在 FINAL-ASSESSMENT.md 里以"每密钥字节的检验次数"记账
```

## 基线（体积 / 冷启动）

```
tools/baseline.json 记录每代的 size 与 cold_s（首次运行用 --update-baseline 生成）
  size     逐字节比对，任何偏差都算 FAIL（几何/元数据是可复现的）
  cold_s   取三次运行的最小值，允许比基线慢 25%（--tol 可调）；单次采样在负载高的机器上会误报
有意改动（换表几何、加字段）之后必须显式刷新基线，否则门会红——这是设计意图：
  体积/耗时的变化必须被"承认过一次"，不能悄悄漂移
```

## 改动类型 → 必跑的最小集合

| 改了什么 | 最小验证 |
|---|---|
| 运行时 / 生成器 / 表布局 | `verify_all.py`（全量） |
| VM 字节码或 pass | `verify_all.py --only <含 VM 的代> --research` + `scripts/verify_vmp_gate.sh` |
| 攻击脚本 | `--attacks` + 手工跑该脚本并在文档里更新数字 |
| 导出 / strip / 硬化 | `verify_all.py` + 抽查 `nm`/`otool -l` + 更新 `sha256.txt` |
| 只改文档 | 无（但文档里出现的"已提取/已修复"必须绑定脚本与命令，见下） |

## 三条事故规则（都是本项目踩过的）

1. **文档里的断言必须绑定"脚本 + 提交 + 命令 + 期望输出"。**
   用私有/实验性 reader 得到的结论不能记在已提交脚本头上——
   曾经 README 写"w16_probe 已出钥"，而它因 loader 几何过期实际输出 `0/16`。
2. **委派回来的"成功"必须至少独立复跑最强的那个声明。**
   只验密文+sha256 不够：那两项在"出钥声明为假"时也照样通过。
3. **负向测试是基本功能的一部分。**
   改调度块字节必须让密文变化、恢复后必须复原；没有这条，VM/封印就只是装饰。

## 加一代新产物时

1. 在 `tools/verify_all.py` 的 `GENERATIONS` 里加一行：`(名称, 二进制名, AES-128 密钥, 期望密文, 是否含 VM)`；
2. 把产物 sha256 追加进 `exported-binaries/wbaes-challenge/macos/sha256.txt`；
3. 跑 `python3 tools/verify_all.py --only <名称>`，确认 6 条全 PASS；
4. 在 `README.md` 的产物表里加行，并写明该代的**强度价位**（每字节检验次数），不是"更强"。
