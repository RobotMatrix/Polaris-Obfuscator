#!/usr/bin/env python3
# 生成文档配图 (matplotlib, 无中文乱码: Hiragino Sans GB)
# 输出: docs/images/{sdk_architecture,decision_chain,protocol_sequence,key_hierarchy}.png
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mp
import os

matplotlib.rcParams["font.family"] = ["Hiragino Sans GB", "STHeiti", "Arial Unicode MS"]
matplotlib.rcParams["axes.unicode_minus"] = False

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "images")
os.makedirs(OUT, exist_ok=True)
DPI = 160

C = {
    "biz": "#E8F1FF", "biz_e": "#4477AA",
    "soft": "#FFF3E0", "soft_e": "#E8961E",
    "risk": "#F3E8FF", "risk_e": "#8A5CC0",
    "crypto": "#E8F8F0", "crypto_e": "#2E9E6B",
    "hw": "#FDE8E8", "hw_e": "#CC4444",
    "srv": "#EEEEEE", "srv_e": "#777777",
}

def box(ax, x, y, w, h, text, fc, ec, fs=10, bold=False):
    ax.add_patch(mp.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02",
                                   fc=fc, ec=ec, lw=1.6))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", linespacing=1.4)

def arrow(ax, x1, y1, x2, y2, style="-|>", color="#555555", lw=1.6, ls="-"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color, lw=lw, linestyle=ls))

# ================= 图1: SDK 六层架构 =================
fig, ax = plt.subplots(figsize=(11.5, 8.2))
ax.set_xlim(0, 10); ax.set_ylim(0, 10.6); ax.axis("off")

ax.text(5, 10.25, "polaris-secure-sdk 分层架构 (参考《跨平台App安全保护架构研究》§15)",
        ha="center", fontsize=13.5, fontweight="bold")

box(ax, 0.3, 9.0, 9.4, 0.85,
    "业务层  App / C++ SDK  —  调用 SecureSDK 统一门面 (不可信)", C["biz"], C["biz_e"], 11, True)
arrow(ax, 5, 9.0, 5, 8.62)

box(ax, 0.3, 7.05, 4.55, 1.55,
    "软件保护层 (编译期)\nPolaris-Obfuscator 9-pass\nalias/gvenc/indcall/indbr/mba\nsub/bcf/fla/merge + WBAES 白盒", C["soft"], C["soft_e"], 9.5)
box(ax, 5.15, 7.05, 4.55, 1.55,
    "风险分析层 (运行时)\nSecuritySensors → 特征(12维)\nint8 MLP (签名校验) + 规则引擎\nPolicyController 确定性门", C["risk"], C["risk_e"], 9.5)
arrow(ax, 2.575, 7.05, 2.575, 6.67)
arrow(ax, 7.425, 7.05, 7.425, 6.67)

box(ax, 0.3, 5.1, 9.4, 1.55,
    "密码服务层  CryptoService (软件密码模块, 非硬件 HSM)\nSHA-256/512 · HMAC · HKDF · AES-CTR‖HMAC AEAD · Ed25519\n密钥策略(用途/可导出) · 生命周期 · 分层密钥派生", C["crypto"], C["crypto_e"], 10)
arrow(ax, 5, 5.1, 5, 4.72)

box(ax, 0.3, 3.15, 9.4, 1.55,
    "硬件信任层  KeyProvider + SecurityCapability 能力探测\n软件后端(测试/降级) · Apple Keychain · Android Keystore(桩) · OH HUKS(桩)\n设备密钥(Ed25519) · 受保护存储 · 单调计数器(防回滚)", C["hw"], C["hw_e"], 10)
arrow(ax, 8.2, 3.15, 8.2, 2.77, color=C["srv_e"], ls="--")
box(ax, 0.3, 1.2, 9.4, 1.55,
    "服务端信任域  AuthorizationServer (生产部署于服务端)\n授权签发/撤销 · 设备注册表 · nonce 防重放 · 风险复核 · 离线材料签发\n服务端根密钥绝不进入客户端", C["srv"], C["srv_e"], 10)
ax.text(0.32, 0.55, "边界原则: 客户端检测均为不可信信号; 授权以服务端签名为准; "
        "模型只输出风险; 确定性门不可被风险分翻案", fontsize=9, color="#666666")
plt.tight_layout()
plt.savefig(f"{OUT}/sdk_architecture.png", dpi=DPI, bbox_inches="tight")
plt.close()

# ================= 图2: 决策链 =================
fig, ax = plt.subplots(figsize=(11.5, 6.8))
ax.set_xlim(0, 10); ax.set_ylim(0, 8.4); ax.axis("off")
ax.text(5, 8.1, "风险决策链 (参考架构 §8.3) — 模型只能让决策变差, 不能翻案",
        ha="center", fontsize=13, fontweight="bold")

box(ax, 0.3, 6.4, 2.6, 1.1, "运行时信号\n(不可信传感器)", C["risk"], C["risk_e"], 10)
box(ax, 3.5, 6.4, 2.6, 1.1, "特征提取与归一化\n12 维 [0,1]", C["risk"], C["risk_e"], 10)
box(ax, 6.7, 6.4, 3.0, 1.1, "int8 MLP 小模型\n(Ed25519 签名校验)", C["risk"], C["risk_e"], 10)
arrow(ax, 2.9, 6.95, 3.5, 6.95); arrow(ax, 6.1, 6.95, 6.7, 6.95)
ax.text(8.2, 6.1, "验签失败 → 规则引擎兜底", ha="center", fontsize=8.5, color="#B03A3A")

box(ax, 6.7, 4.9, 3.0, 1.1, "风险分 [0,1]\n(仅 advisory)", "#FFFFFF", C["risk_e"], 10)
arrow(ax, 8.2, 6.4, 8.2, 6.0)

box(ax, 0.3, 4.9, 5.8, 1.1, "策略控制器 PolicyController", C["crypto"], C["crypto_e"], 11, True)
arrow(ax, 6.7, 5.45, 6.1, 5.45)
ax.text(3.2, 4.45, "确定性门 (不可妥协): license_valid · integrity_ok · protocol_fresh",
        ha="center", fontsize=9.5, color="#1B6B45")

for i, (txt, col) in enumerate([("确定性完整性检查", None), ("授权状态验证", None),
                                 ("TEE/KeyProvider 结果", None), ("服务端策略(在线)", None)]):
    box(ax, 0.3 + i * 2.42, 3.0, 2.2, 0.95, txt, "#FFFFFF", C["crypto_e"], 9)
    arrow(ax, 1.4 + i * 2.42, 3.95, 1.4 + i * 2.42, 4.9, style="<|-")

for i, (txt, fc, ec) in enumerate([("Allow", "#E8F8F0", "#2E9E6B"),
                                    ("AllowDegraded", "#FFF3E0", "#E8961E"),
                                    ("Deny", "#FDE8E8", "#CC4444")]):
    box(ax, 1.2 + i * 2.9, 1.3, 2.3, 0.95, txt, fc, ec, 11, True)
    arrow(ax, 2.35 + i * 2.9, 3.0, 2.35 + i * 2.9, 2.25)
ax.text(5, 0.55, "不变量: 任一确定性门失败 ⇒ Deny (即使风险分被 Hook 为 0)",
        ha="center", fontsize=10, color="#B03A3A", fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUT}/decision_chain.png", dpi=DPI, bbox_inches="tight")
plt.close()

# ================= 图3: 在线授权时序 =================
fig, ax = plt.subplots(figsize=(11.5, 7.2))
ax.set_xlim(0, 10); ax.set_ylim(0, 8.8); ax.axis("off")
ax.text(5, 8.5, "在线授权协议 (挑战-应答, §9.1) — 时序与攻击面", ha="center",
        fontsize=13, fontweight="bold")

lifelines = [("客户端\n(普通环境)", 1.6, C["biz"], C["biz_e"]),
             ("SecureSDK\n+KeyProvider", 4.4, C["hw"], C["hw_e"]),
             ("授权服务器\n(信任域)", 8.0, C["srv"], C["srv_e"])]
for name, x, fc, ec in lifelines:
    box(ax, x - 1.05, 7.5, 2.1, 0.8, name, fc, ec, 9.5, True)
    ax.plot([x, x], [0.6, 7.5], color=ec, lw=1.2, ls="--")

msgs = [
    (7.2, 4.4, 8.0, "① ClientHello  device_id · client_nonce · features", C["srv_e"]),
    (6.6, 8.0, 4.4, "② ServerChallenge  server_nonce(签发者签名) · ts", C["srv_e"]),
    (6.0, 4.4, 8.0, "③ ClientAttest  设备密钥签名(nonce‖nonce‖请求哈希) · 风险分", C["srv_e"]),
    (5.3, 8.0, 4.4, "④ ServerGrant  短期License(绑定 challengeHash, TTL=5min)", "#2E9E6B"),
]
for y, x1, x2, txt, color in msgs:
    arrow(ax, x1, y, x2, y, color=color, lw=1.8)
    ax.text((x1 + x2) / 2, y + 0.14, txt, ha="center", fontsize=8.8, color=color)

box(ax, 0.15, 3.9, 3.1, 1.5, "⑤ 本地独立复核\n签名·设备绑定·时间窗\nserial 水位·计数器·挑战绑定",
    C["crypto"], C["crypto_e"], 8.8)
arrow(ax, 4.4, 4.65, 3.25, 4.65, color=C["crypto_e"])

attacks = [
    (2.9, "攻击面: ③ 重放 (nonce 已用/挑战已消费) → ReplayDetected"),
    (2.35, "攻击面: ③ 伪造设备签名 → AttestBadSignature"),
    (1.8, "攻击面: ④ 中间人篡改 grant → 本地复核 BadSignature"),
    (1.25, "攻击面: 撤销设备 → DeviceRevoked"),
]
for y, txt in attacks:
    ax.text(0.15, y, "✗ " + txt, fontsize=8.8, color="#B03A3A")
ax.text(4.5, 0.75, "接受授权 ⇒ serial 水位写入受保护存储 + 设备计数器 bump (防回滚)",
        ha="center", fontsize=9.5, color="#1B6B45")
plt.tight_layout()
plt.savefig(f"{OUT}/protocol_sequence.png", dpi=DPI, bbox_inches="tight")
plt.close()

# ================= 图4: 分层密钥体系 =================
fig, ax = plt.subplots(figsize=(11.5, 6.4))
ax.set_xlim(0, 10); ax.set_ylim(0, 8.0); ax.axis("off")
ax.text(5, 7.7, "分层密钥体系 (§7.3) — 服务端根密钥绝不进入客户端", ha="center",
        fontsize=13, fontweight="bold")

tiers = [
    (6.3, "服务端信任域", [("服务端根密钥\n(仅服务端)", 2.0), ("授权签名密钥\nEd25519", 5.0), ("模型签名密钥\nEd25519", 8.0)], C["srv"], C["srv_e"]),
    (4.2, "设备侧 (硬件保护)", [("设备密钥\nKeyProvider/TEE", 2.0), ("受保护存储\nserial 水位·计数器", 5.0), ("设备身份 ID\nSHA256(pk)", 8.0)], C["hw"], C["hw_e"]),
    (2.1, "运行时派生 (HKDF)", [("会话密钥", 2.0), ("代码加密密钥\n(按版本)", 5.0), ("数据密钥\n(按上下文)", 8.0)], C["crypto"], C["crypto_e"]),
]
for y, label, items, fc, ec in tiers:
    ax.text(0.25, y + 0.85, label, fontsize=10.5, fontweight="bold", color=ec)
    for txt, x in items:
        box(ax, x - 1.35, y, 2.7, 1.05, txt, fc, ec, 9.5)
arrow(ax, 3.35, 4.2, 2.0, 3.15, ls="--"); arrow(ax, 6.35, 4.2, 5.0, 3.15, ls="--")
arrow(ax, 9.35, 4.2, 8.0, 3.15, ls="--")
ax.text(5, 1.35, "派生密钥不出 CryptoService; SecureBuffer 析即焚毁 (密钥卫生)",
        ha="center", fontsize=9.5, color="#666666")
ax.text(5, 0.7, "客户端内置常量不得当作秘密根密钥 (§7.3 红线)", ha="center",
        fontsize=10, color="#B03A3A", fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUT}/key_hierarchy.png", dpi=DPI, bbox_inches="tight")
plt.close()

print("generated:", os.listdir(OUT))
