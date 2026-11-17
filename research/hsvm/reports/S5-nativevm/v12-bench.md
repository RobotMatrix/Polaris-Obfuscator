# 契约扩展与性能测量（compiled vs interpreted）

## 一、契约扩展：`hsvm_entry` 支持 `i32 (i32)`

原契约 `i32 ()` 的初始寄存器只能来自 `@hsvm_init`（编译期常量），于是：
- 优化器可以把整段程序折叠掉，性能无从测；
- pass 对真实程序没用——没有运行时输入。

现在 `hsvm_entry` 接受 `i32 ()` 或 `i32 (i32)`：一个参数时，参数值作为初始寄存器填充。
`@hsvm_init` 仍然作为无参形式的缺省。`research/hsvm/tools/hsvm_bench.cpp` 就靠它把
trips 从 `argv` 喂进去。

## 二、实测（arm64 macOS，`-O1`，1,000,000 次循环）

```
result       : interp=1784293664 native=1784293664 MATCH
trips        : 1000000
interpreter  : 9.069996 s
native (pass): 0.005481 s
speedup      : 1654.84x   (compiled vs interpreted; NOT R_plain)
```

每次迭代 4 条指令（`add / sub / brz / jmp`），所以解释器侧约 4M 步、约 2.3 µs/步。

## 三、这个数字不能怎么用（重要）

1. **它不是 `R_plain`。** 文档 §5.5 的口径是"受保护 VM 相对朴素基线"，尺子是 4.2–4.34 ns 基线、
   cap 3.0；本测量的分子分母都不是那两样东西，禁止替换尺子，也禁止引用成"我们的保护达到 X 倍"。
2. **1655× 严重高估了"解释执行 vs 编译"的真实差距。** 这里的解释器是研究层的 `Machine`：
   每步都要维护 `BitVector` 状态（C1 模型需要），不是生产级的 switch-dispatch 解释器。
   一个正常的 switch 解释器通常只比编译代码慢 10–50×。
   换成生产解释器做分母，这个数字会掉一到两个数量级。
3. 只跑过 arm64 macOS，只测了一个循环体形状（无访存），没有测访存密集与不同 w/c 参数。

## 四、测量过程中被发现的一个坑

`Machine::run()` 的默认 `maxSteps` 是 **1,000,000**。第一次跑 1M trips 时解释器被这个上限截断，
原生程序却跑完了全程：结果是 `MISMATCH`，而且解释器耗时在 200k/1M/4M 三个规模上几乎不变
（1.79s / 1.79s / 1.80s）——这个"耗时与规模无关"就是截断的信号。

修法：显式 `run(50000000u)`。**教训：任何性能比较必须先断言两边结果相同**，
否则测的是两段不同的工作。现在 `hsvm_bench` 在结果不同时返回 1，ctest `bench_match`
（26 个测试之一）跑 20,000 trips 只断言 `MATCH`，不断言耗时——耗时是信息，不是判据。

## 五、复现

```bash
cd research/hsvm && cmake --build build -j10
HSV_CLANG=$PWD/../../src/build/bin/clang ./build/hsvm_bench 1000000 /tmp/hsvm_bench
ctest --test-dir build -R bench_match
```
