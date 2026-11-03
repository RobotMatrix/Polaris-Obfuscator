// test_dart.dart — Dart/Flutter FFI × 白盒 AES dylib
// 覆盖: FFI 绑定/Dart 类/泛型/async/extension/mixin/工厂模式/Stream
// 
// 前置: libwbaes.dylib 与本文件同目录 (或指定路径)
// 运行: dart run test_dart.dart
//
// Dart FFI 通过 C wrapper (wbaes_c_wrapper.h 的 C ABI) 调用白盒 —
// 这也是 iOS/Android Flutter 插件的标准集成方式

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'dart:convert';

// ===== FFI 绑定 =====
// C ABI: void* wbaes_create(); void wbaes_encrypt(void*, const uint8_t*, uint8_t*); ...
final class WBAESBindings {
  late ffi.DynamicLibrary _lib;
  late ffi.Pointer<ffi.Void> _handle;

  WBAESBindings([String? path]) {
    _lib = ffi.DynamicLibrary.open(path ?? 'libwbaes.dylib');
    final create = _lib.lookupFunction<ffi.Pointer<ffi.Void> Function(),
        ffi.Pointer<ffi.Void> Function()>('wbaes_create');
    _handle = create();
  }

  void encrypt(Uint8List input, Uint8List output) {
    final enc = _lib.lookupFunction<
        ffi.Void Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>),
        void Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>)>('wbaes_encrypt');
    final inBuf = calloc<ffi.Uint8>(16);
    final outBuf = calloc<ffi.Uint8>(16);
    inBuf.asTypedList(16).setAll(0, input);
    enc(_handle, inBuf, outBuf);
    output.setAll(0, outBuf.asTypedList(16));
    calloc.free(inBuf);
    calloc.free(outBuf);
  }

  void decrypt(Uint8List input, Uint8List output) {
    final dec = _lib.lookupFunction<
        ffi.Void Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>),
        void Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>)>('wbaes_decrypt');
    final inBuf = calloc<ffi.Uint8>(16);
    final outBuf = calloc<ffi.Uint8>(16);
    inBuf.asTypedList(16).setAll(0, input);
    dec(_handle, inBuf, outBuf);
    output.setAll(0, outBuf.asTypedList(16));
    calloc.free(inBuf);
    calloc.free(outBuf);
  }

  void dispose() {
    final destroy =
        _lib.lookupFunction<ffi.Void Function(ffi.Pointer<ffi.Void>),
            void Function(ffi.Pointer<ffi.Void>)>('wbaes_destroy');
    destroy(_handle);
  }
}

// calloc 简写 (dart:ffi 内置)
const calloc = ffi;

// ===== 泛型加密服务类 =====
class CryptoService<T extends List<int>> {
  final WBAESBindings _bindings;
  CryptoService(this._bindings);

  Uint8List encryptBlock(Uint8List input) {
    if (input.length != 16) throw ArgumentError('block must be 16 bytes');
    final out = Uint8List(16);
    _bindings.encrypt(input, out);
    return out;
  }

  Uint8List decryptBlock(Uint8List input) {
    if (input.length != 16) throw ArgumentError('block must be 16 bytes');
    final out = Uint8List(16);
    _bindings.decrypt(input, out);
    return out;
  }

  // 多块 ECB
  Uint8List encryptData(Uint8List data) {
    final out = Uint8List(data.length);
    for (int i = 0; i + 16 <= data.length; i += 16) {
      _bindings.encrypt(
          Uint8List.sublistView(data, i, i + 16),
          Uint8List.sublistView(out, i, i + 16));
    }
    return out;
  }

  Uint8List decryptData(Uint8List data) {
    final out = Uint8List(data.length);
    for (int i = 0; i + 16 <= data.length; i += 16) {
      _bindings.decrypt(
          Uint8List.sublistView(data, i, i + 16),
          Uint8List.sublistView(out, i, i + 16));
    }
    return out;
  }
}

// ===== Extension 语法糖 =====
extension CryptoExt on Uint8List {
  Uint8List get xored => Uint8List.fromList(map((b) => b ^ 0xFF).toList());
  String toHex() => map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

// ===== Mixin =====
mixin CryptoMixin {
  int roundCount = 0;
  void incrementRound() => roundCount++;
}

// ===== Factory + Singleton =====
class CryptoFactory {
  static CryptoService? _instance;
  static CryptoService get instance {
    _instance ??= CryptoService(WBAESBindings());
    return _instance!;
  }
}

// ===== async/Stream =====
Stream<Uint8List> encryptStream(
    CryptoService svc, Stream<Uint8List> blocks) async* {
  await for (final block in blocks) {
    yield svc.encryptBlock(block);
  }
}

void main() async {
  int fails = 0;
  final bindings = WBAESBindings();
  final svc = CryptoService(bindings);

  // 1. 基础 roundtrip
  final pt = Uint8List.fromList(List.generate(16, (i) => i));
  final ct = svc.encryptBlock(pt);
  final rt = svc.decryptBlock(ct);
  final ok1 = List Equality(pt, rt);
  // 简化比较
  bool same = true;
  for (int i = 0; i < 16; i++) if (pt[i] != rt[i]) same = false;
  if (!same) fails++;
  print('[Dart basic] ${same ? "PASS" : "FAIL"} (ct=${ct.toHex()})');

  // 2. 多块 ECB
  final data = Uint8List(64);
  for (int i = 0; i < 64; i++) data[i] = i;
  final enc = svc.encryptData(data);
  final dec = svc.decryptData(enc);
  same = true;
  for (int i = 0; i < 64; i++) if (data[i] != dec[i]) same = false;
  if (!same) fails++;
  print('[Dart multi-block] ${same ? "PASS" : "FAIL"}');

  // 3. Extension
  final xored = pt.xored;
  same = true;
  for (int i = 0; i < 16; i++) if (xored[i] != (pt[i] ^ 0xFF)) same = false;
  if (!same) fails++;
  print('[Dart extension] ${same ? "PASS" : "FAIL"}');

  // 4. async/Stream
  final stream = Stream<Uint8List>.fromIterable([pt, pt, pt]);
  final results = <Uint8List>[];
  await for (final block in encryptStream(svc, stream)) {
    results.add(block);
  }
  same = true;
  for (final r in results) {
    final d = svc.decryptBlock(r);
    for (int i = 0; i < 16; i++) if (d[i] != pt[i]) same = false;
  }
  if (!same) fails++;
  print('[Dart async-stream] ${same ? "PASS" : "FAIL"} (${results.length} blocks)');

  // 5. 泛型 + mixin
  final factory_svc = CryptoFactory.instance;
  final t1 = Uint8List.fromList(List.generate(16, (i) => i * 7));
  final tc = factory_svc.encryptBlock(t1);
  final tr = factory_svc.decryptBlock(tc);
  same = true;
  for (int i = 0; i < 16; i++) if (t1[i] != tr[i]) same = false;
  if (!same) fails++;
  print('[Dart factory-generic] ${same ? "PASS" : "FAIL"}');

  bindings.dispose();
  print(fails ? 'Dart TOTAL: $fails FAILS' : 'Dart TOTAL: ALL PASS');
  exit(fails > 0 ? 1 : 0);
}

// 简单相等检查
bool ListEquality(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
  return true;
}
