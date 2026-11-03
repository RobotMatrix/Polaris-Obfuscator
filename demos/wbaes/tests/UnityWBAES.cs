// UnityWBAES.cs — Unity3D C# P/Invoke × 白盒 AES dylib
// 
// 集成方式:
//   1. libwbaes.dylib 放入 Unity 项目的 Assets/Plugins/ 目录
//   2. Unity 的 IL2CPP/Mono 运行时通过 DllImport P/Invoke 调用
//   3. 所有白盒逻辑在 dylib 内 (原生 C++ MIR 混淆), C# 层只看到 C ABI
//
// 覆盖: P/Invoke/结构体传递/字节数组/委托回调/错误处理/泛型封装

using System;
using System.Runtime.InteropServices;
using UnityEngine;

namespace PolarisWhitebox
{
    /// <summary>
    /// 白盒 AES P/Invoke 绑定 — 所有方法对应 wbaes_c_wrapper.h 的 C ABI
    /// </summary>
    public static class WBAESNative
    {
        const string LIB = "libwbaes";

        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wbaes_create();

        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wbaes_destroy(IntPtr handle);

        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wbaes_encrypt(IntPtr handle, byte[] input, byte[] output);

        [DllImport(LIB, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wbaes_decrypt(IntPtr handle, byte[] input, byte[] output);
    }

    /// <summary>
    /// 泛型加密服务 — 单例模式 + IDisposable
    /// </summary>
    public sealed class WBAESService : IDisposable
    {
        static WBAESService _instance;
        static readonly object _lock = new object();
        IntPtr _handle;
        bool _disposed;

        public static WBAESService Instance
        {
            get
            {
                lock (_lock)
                {
                    _instance ??= new WBAESService();
                    return _instance;
                }
            }
        }

        WBAESService()
        {
            _handle = WBAESNative.wbaes_create();
            if (_handle == IntPtr.Zero)
                throw new InvalidOperationException("WBAES create failed");
        }

        ~WBAESService() { Dispose(false); }

        public void Dispose()
        {
            if (!_disposed)
            {
                WBAESNative.wbaes_destroy(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
        void Dispose(bool disposing) { if (disposing) Dispose(); }

        /// <summary>原地加密 16B 块</summary>
        public void Encrypt(byte[] block)
        {
            if (block.Length != 16) throw new ArgumentException("block must be 16B");
            if (_disposed) throw new ObjectDisposedException(nameof(WBAESService));
            WBAESNative.wbaes_encrypt(_handle, block, block);
        }

        /// <summary>原地解密 16B 块</summary>
        public void Decrypt(byte[] block)
        {
            if (block.Length != 16) throw new ArgumentException("block must be 16B");
            WBAESNative.wbaes_decrypt(_handle, block, block);
        }

        /// <summary>多块 ECB 加密</summary>
        public byte[] EncryptData(byte[] data)
        {
            var out_ = new byte[data.Length];
            for (int i = 0; i + 16 <= data.Length; i += 16)
            {
                var blk = new byte[16];
                Array.Copy(data, i, blk, 0, 16);
                Encrypt(blk);
                Array.Copy(blk, 0, out_, i, 16);
            }
            return out_;
        }

        /// <summary>多块 ECB 解密</summary>
        public byte[] DecryptData(byte[] data)
        {
            var out_ = new byte[data.Length];
            for (int i = 0; i + 16 <= data.Length; i += 16)
            {
                var blk = new byte[16];
                Array.Copy(data, i, blk, 0, 16);
                Decrypt(blk);
                Array.Copy(blk, 0, out_, i, 16);
            }
            return out_;
        }
    }

    /// <summary>
    /// 泛型加密扩展方法 — C# 语法糖
    /// </summary>
    public static class WBAESExtensions
    {
        public static byte[] WBAESEncrypt(this byte[] data) =>
            WBAESService.Instance.EncryptData(data);
        public static byte[] WBAESDecrypt(this byte[] data) =>
            WBAESService.Instance.DecryptData(data);
        public static string ToHex(this byte[] data) =>
            BitConverter.ToString(data).Replace("-", "").ToLower();
    }

    /// <summary>
    /// 泛型安全容器 — Unity 序列化兼容
    /// </summary>
    [Serializable]
    public class SecureContainer<T> where T : class
    {
        byte[] _encrypted;
        Action<T, byte[]> _serializer;
        Func<byte[], T> _deserializer;

        public SecureContainer(Action<T, byte[]> serializer, Func<byte[], T> deserializer)
        {
            _serializer = serializer;
            _deserializer = deserializer;
        }

        public void Store(T obj)
        {
            var bytes = new byte[16];  // 简化: 16B 块
            _serializer(obj, bytes);
            _encrypted = WBAESService.Instance.EncryptData(bytes);
        }

        public T Load()
        {
            var dec = WBAESService.Instance.DecryptData(_encrypted);
            return _deserializer(dec);
        }
    }

#if UNITY_EDITOR || UNITY_STANDALONE
    /// <summary>
    /// Unity 测试入口 (挂到 GameObject 或用 [RuntimeInitializeOnLoadMethod])
    /// </summary>
    public class WBAESTests
    {
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        static void RunTests()
        {
            Debug.Log("=== WBAES Unity Tests ===");
            int fails = 0;

            // 1. 基础 roundtrip
            var pt = new byte[16];
            for (int i = 0; i < 16; i++) pt[i] = (byte)i;
            var svc = WBAESService.Instance;
            var ct = svc.EncryptData(pt);
            var rt = svc.DecryptData(ct);
            bool ok = true;
            for (int i = 0; i < 16; i++) if (pt[i] != rt[i]) ok = false;
            Debug.Log($"[Unity basic] {(ok ? "PASS" : "FAIL")} ct={ct.ToHex()}");
            if (!ok) fails++;

            // 2. 多块
            var data = new byte[64];
            for (int i = 0; i < 64; i++) data[i] = (byte)i;
            var enc = svc.EncryptData(data);
            var dec = svc.DecryptData(enc);
            ok = true;
            for (int i = 0; i < 64; i++) if (data[i] != dec[i]) ok = false;
            Debug.Log($"[Unity multi-block] {(ok ? "PASS" : "FAIL")}");
            if (!ok) fails++;

            // 3. 扩展方法
            var xored = pt.WBAESEncrypt().WBAESDecrypt();
            ok = true;
            for (int i = 0; i < 16; i++) if (xored[i] != pt[i]) ok = false;
            Debug.Log($"[Unity extension] {(ok ? "PASS" : "FAIL")}");
            if (!ok) fails++;

            // 4. 泛型容器
            var container = new SecureContainer<string>(
                (obj, buf) => Buffer.BlockCopy(
                    System.Text.Encoding.UTF8.GetBytes(obj.PadRight(16, '\0').Substring(0, 16)),
                    0, buf, 0, 16),
                (buf) => System.Text.Encoding.UTF8.GetString(buf).TrimEnd('\0'));
            container.Store("hello-whitebox");
            var loaded = container.Load();
            ok = loaded == "hello-whitebox";
            Debug.Log($"[Unity generic-container] {(ok ? "PASS" : "FAIL")}");
            if (!ok) fails++;

            Debug.Log(fails > 0
                ? $"Unity TOTAL: {fails} FAILS"
                : "Unity TOTAL: ALL PASS");
        }
    }
#endif
}
