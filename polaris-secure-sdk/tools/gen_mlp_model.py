#!/usr/bin/env python3
# 生成风险分析层小模型 (12→8→1 int8 MLP) 待签名模型包
# 输出: build/risk_model_unsigned.bin (待签正文)
# 训练数据: 确定性合成规则 (seed 固定), 设计详见 docs/04。
import numpy as np
import struct
import os

np.random.seed(20261111)
FEATS = 12
HID = 8

def true_risk(x):
    """合成风险函数: 主因子 + 组合放大 + 硬性因子 (训练标签来源)"""
    w = np.array([0.30, 0.16, 0.14, 0.12, 0.08, 0.05, 0.04, 0.04, 0.03, 0.02, 0.02, 0.01])
    base = float(np.dot(x, w))
    # 组合效应: 前四类中强度信号同时出现 → 风险超线性 (§8.1 多个低置信度异常组合)
    combo = float(np.all(x[:4] > 0.5)) * 0.15
    # 硬性因子: 完整性失败 / 证明失败 直接抬升
    hard = 0.35 * max(x[0], x[10])
    return float(np.clip(base + combo + hard, 0, 1))

X = np.random.rand(6000, FEATS).astype(np.float32)
# 低风险区域加密采样 (干净基线精度重要)
X[:1200] = np.random.rand(1200, FEATS).astype(np.float32) * 0.15
X[0] = 0                                            # 全干净
X[1] = 1                                            # 全异常
X[2] = 0; X[2][0] = 1                               # 仅完整性失败
X[3] = 0; X[3][10] = 1                              # 仅证明失败
X[4] = 0; X[4][2] = 0.6; X[4][6] = 0.5              # 组合中等信号
y = np.array([true_risk(xi) for xi in X], dtype=np.float32)

# --- 训练 12→8→1 (ReLU 隐层 + sigmoid 输出, Adam, float64) ---
X64 = X.astype(np.float64)
y64 = y.astype(np.float64)
W1 = np.random.randn(FEATS, HID) * np.sqrt(2.0 / FEATS)
b1 = np.zeros(HID)
W2 = np.random.randn(HID) * np.sqrt(2.0 / HID)
b2 = np.zeros(1)
params = [W1, b1, W2, b2]
m = [np.zeros_like(p) for p in params]
v = [np.zeros_like(p) for p in params]
lr, b1a, b2a, eps = 0.01, 0.9, 0.999, 1e-8
n = len(X64)
for step in range(1, 3001):
    z1 = X64 @ W1 + b1
    a1 = np.maximum(z1, 0)
    out = 1 / (1 + np.exp(-np.clip(a1 @ W2 + b2, -30, 30)))
    err = (out - y64) / n
    d2 = (err * out * (1 - out)).reshape(-1, 1)
    gW2 = (a1 * d2).sum(0)
    gb2 = d2.sum(0)
    dz1 = (d2 * W2.reshape(1, -1)) * (z1 > 0)
    gW1 = X64.T @ dz1
    gb1 = dz1.sum(0)
    grads = [gW1, gb1, gW2, gb2]
    for i, (p, g) in enumerate(zip(params, grads)):
        m[i] = b1a * m[i] + (1 - b1a) * g
        v[i] = b2a * v[i] + (1 - b2a) * g * g
        mh = m[i] / (1 - b1a ** step)
        vh = v[i] / (1 - b2a ** step)
        p -= lr * mh / (np.sqrt(vh) + eps)

z1 = X64 @ W1 + b1
a1 = np.maximum(z1, 0)
out = 1 / (1 + np.exp(-np.clip(a1 @ W2 + b2, -30, 30)))
mae = float(np.abs(out - y).mean())
print(f"train MAE = {mae:.4f}")
assert mae < 0.05, f"训练未收敛 MAE={mae}"

# --- int8 对称量化 (每张量独立尺度; 存储压缩+完整性锚定, 推理时反量化) ---
def q(arr):
    s = float(np.max(np.abs(arr))) / 127.0
    qi = np.round(arr / s).astype(np.int8)
    return qi, s

qW1, s_w1 = q(W1)
qb1, s_b1 = q(b1)
qW2, s_w2 = q(W2)
qb2v, s_b2 = q(b2)
qb2 = int(qb2v[0])

def infer2(x):
    # 与 C++ 运行时一致: 反量化 → ReLU 隐层 → sigmoid 输出
    W1f = qW1.astype(np.float64) * s_w1
    b1f = qb1.astype(np.float64) * s_b1
    W2f = qW2.astype(np.float64) * s_w2
    b2f = qb2 * s_b2
    h = np.maximum(x.astype(np.float64) @ W1f + b1f, 0)
    z = h @ W2f + b2f
    return float(1 / (1 + np.exp(-np.clip(z, -30, 30))))

probe = {
    "clean": infer2(np.zeros(FEATS)),
    "all": infer2(np.ones(FEATS)),
    "integrity_only": infer2(np.array([1] + [0] * 11, dtype=float)),
    "combo_mid": infer2(np.array([0, 0, .6, .6, .5, .5, 0, 0, 0, 0, 0, 0])),
    "debugger_only": infer2(np.array([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], dtype=float)),
}
print("probe:", {k: round(v, 3) for k, v in probe.items()})
assert probe["clean"] < 0.15 and probe["all"] > 0.90
assert probe["integrity_only"] > 0.45  # 硬性因子应显著抬升
assert probe["debugger_only"] > 0.08   # 单一 debugger 信号有正向输出

# --- 打包待签正文 ---
# PRM1 | ver u32 | feats u32 | hid u32 | w1 | b1 | w2 | b2(int8) | 4×scale f32
blob = b"PRM1" + struct.pack("<III", 1, FEATS, HID)
blob += qW1.tobytes() + qb1.tobytes() + qW2.tobytes() + struct.pack("<b", qb2)
blob += struct.pack("<ffff", s_w1, s_b1, s_w2, s_b2)
os.makedirs("build", exist_ok=True)
with open("build/risk_model_unsigned.bin", "wb") as f:
    f.write(blob)
print("wrote build/risk_model_unsigned.bin", len(blob), "bytes")
print("tensor scales:", round(s_w1,6), round(s_b1,6), round(s_w2,6), round(s_b2,6))

# 同时生成 C++ 内嵌头 (供测试/混淆矩阵构建使用, 免文件路径依赖)
with open("src/risk_model_data.h", "w") as f:
    f.write("// 自动生成 by tools/gen_mlp_model.py — 请勿手改\n")
    f.write("// int8 量化 MLP 模型参数 (12→8→1, ReLU 隐层, sigmoid 输出)\n")
    f.write("#pragma once\n#include <cstdint>\n#include <cstddef>\n\n")
    f.write("namespace polaris_secure {\n")
    f.write("inline constexpr uint8_t kRiskModelBlob[] = {\n")
    for i in range(0, len(blob), 16):
        row = ", ".join(f"0x{b:02x}" for b in blob[i:i+16])
        f.write(f"    {row},\n")
    f.write("};\n")
    f.write(f"inline constexpr size_t kRiskModelBlobSize = {len(blob)};\n")
    f.write("}  // namespace polaris_secure\n")
print("wrote src/risk_model_data.h")
