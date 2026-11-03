#!/bin/bash
# Polaris-Obfuscator build script
# Detects host arch and configures targets accordingly:
#   - Apple Silicon (arm64 mac): builds AArch64+X86 backends, defaults to
#     arm64-apple-macos triple with the active SDK as default sysroot, so the
#     produced clang works out-of-the-box on this machine.
#   - Linux x86_64: original behavior (X86 only).
#
# Note: MIR-level (backend) obfuscation ("backend-obfu") is implemented in
# X86RubbishCode.cpp and therefore only applies to x86_64 targets. On arm64
# targets the IR-level passes work; use -arch x86_64 for backend obfuscation.
set -e

cd src
mkdir -p build
cd build

HOST_ARCH=$(uname -m)

if [ "$(uname)" = "Darwin" ]; then
    if [ "$HOST_ARCH" = "arm64" ]; then
        SDK=$(xcrun --show-sdk-path)
        cmake -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DLLVM_ENABLE_PROJECTS="clang" \
            -DLLVM_TARGETS_TO_BUILD="AArch64;X86" \
            -DLLVM_ENABLE_ASSERTIONS=Off \
            -DLLVM_DEFAULT_TARGET_TRIPLE="arm64-apple-macos13.0.0" \
            -DLLVM_HOST_TRIPLE="arm64-apple-macos13.0.0" \
            -DDEFAULT_SYSROOT="$SDK" \
            ../llvm
    else
        cmake -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DLLVM_ENABLE_PROJECTS="clang" \
            -DLLVM_TARGETS_TO_BUILD="X86" \
            -DLLVM_ENABLE_ASSERTIONS=Off \
            ../llvm
    fi
else
    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_PROJECTS="clang" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_ENABLE_ASSERTIONS=Off \
        ../llvm
fi

cmake --build . --target clang
