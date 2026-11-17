# polaris-secure-sdk — 跨平台 App 安全保护架构参考实现
# 依赖: 仅 C++17 标准库 + 平台系统库 (Apple: CoreFoundation/Security)
# 用法:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build && ctest --test-dir build
cmake_minimum_required(VERSION 3.16)
project(polaris-secure-sdk CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 密码原语源文件虽为 .c 后缀, 但使用 C++ 命名空间 → 按 C++ 编译
set_source_files_properties(
    src/crypto/sha2.c src/crypto/aes_wrap.c src/crypto/ed25519.c third_party/tiny_aes.c
    PROPERTIES LANGUAGE CXX)

add_library(polaris_secure STATIC
    src/crypto/sha2.c
    src/crypto/aes_wrap.c
    src/crypto/ed25519.c
    third_party/tiny_aes.c
    src/key_provider.cpp
    src/crypto_service.cpp
    src/license.cpp
    src/protocol.cpp
    src/server/authorization_server.cpp
    src/risk_model.cpp
    src/secure_sdk.cpp
)
target_include_directories(polaris_secure PUBLIC include third_party)

if(APPLE)
    target_link_libraries(polaris_secure PRIVATE "-framework CoreFoundation" "-framework Security")
endif()

enable_testing()

# ---- 测试矩阵 ----
function(polaris_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE polaris_secure)
    target_include_directories(${name} PRIVATE tests src)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

polaris_test(test_crypto_kat)
polaris_test(test_crypto_service)
polaris_test(test_license)
polaris_test(test_protocol_online)
polaris_test(test_risk_policy)
polaris_test(test_integration)

# ---- 一致性载荷 (混淆矩阵用: 输出确定性结果流) ----
add_executable(conformance tools/conformance.cpp)
target_link_libraries(conformance PRIVATE polaris_secure)
target_include_directories(conformance PRIVATE src)

# ---- 性能基准 ----
add_executable(bench_core tools/bench_core.cpp)
target_link_libraries(bench_core PRIVATE polaris_secure)
target_include_directories(bench_core PRIVATE src)
