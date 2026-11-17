# HSV research harness (M0)
#
# Pure C++17 + ctest. No external dependencies by design: the model kernel must
# build on a bare machine and with the project's own clang.
cmake_minimum_required(VERSION 3.16)
project(hsvm_research LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Provenance is captured at configure time so a build directory reports the
# commit it was configured against, not whatever HEAD is later.
execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../..
  OUTPUT_VARIABLE HSV_GIT_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT HSV_GIT_COMMIT)
  set(HSV_GIT_COMMIT "unknown")
endif()
string(TIMESTAMP HSV_BUILD_TIME "%Y-%m-%dT%H:%M:%SZ" UTC)

enable_testing()

add_library(hsvm_core STATIC
  src/gf2.cpp
  src/params.cpp
  src/instr.cpp
  src/machine.cpp
  src/programs.cpp
  src/psi.cpp
    src/c6.cpp
    src/modenc.cpp
  src/model.cpp
)
target_include_directories(hsvm_core PUBLIC include)
target_compile_options(hsvm_core PRIVATE -Wall -Wextra)
target_compile_definitions(hsvm_core PRIVATE
  HSV_GIT_COMMIT="${HSV_GIT_COMMIT}"
  HSV_BUILD_TIME="${HSV_BUILD_TIME}"
  HSV_KERNEL_VERSION="hsvm-core-0.2")

# --- tools -----------------------------------------------------------------
add_executable(hsvm_params tools/hsvm_params.cpp)
target_link_libraries(hsvm_params PRIVATE hsvm_core)
target_compile_options(hsvm_params PRIVATE -Wall -Wextra)

add_executable(hsvm_run tools/hsvm_run.cpp)
target_link_libraries(hsvm_run PRIVATE hsvm_core)
target_compile_options(hsvm_run PRIVATE -Wall -Wextra)

add_executable(hsvm_gamma tools/hsvm_gamma.cpp)
target_link_libraries(hsvm_gamma PRIVATE hsvm_core)
target_compile_options(hsvm_gamma PRIVATE -Wall -Wextra)

add_executable(hsvm_affine_recover tools/hsvm_affine_recover.cpp)
target_link_libraries(hsvm_affine_recover PRIVATE hsvm_core)
target_compile_options(hsvm_affine_recover PRIVATE -Wall -Wextra)

add_executable(hsvm_ddt tools/hsvm_ddt.cpp)
target_link_libraries(hsvm_ddt PRIVATE hsvm_core)
target_compile_options(hsvm_ddt PRIVATE -Wall -Wextra)

add_executable(hsvm_games tools/hsvm_games.cpp)
target_link_libraries(hsvm_games PRIVATE hsvm_core)
target_compile_options(hsvm_games PRIVATE -Wall -Wextra)

add_executable(hsvm_normalize tools/hsvm_normalize.cpp)
target_link_libraries(hsvm_normalize PRIVATE hsvm_core)
target_compile_options(hsvm_normalize PRIVATE -Wall -Wextra)

add_executable(hsvm_floor tools/hsvm_floor.cpp)
target_link_libraries(hsvm_floor PRIVATE hsvm_core)
target_compile_options(hsvm_floor PRIVATE -Wall -Wextra)

# --- tests -----------------------------------------------------------------
# One binary per area so a failure names the area, as in polaris-secure-sdk.
add_executable(test_smoke tests/test_smoke.cpp)
target_link_libraries(test_smoke PRIVATE hsvm_core)

add_executable(test_gf2 tests/test_gf2.cpp)
target_link_libraries(test_gf2 PRIVATE hsvm_core)
target_compile_options(test_gf2 PRIVATE -Wall -Wextra)

add_executable(test_params tests/test_params.cpp)
target_link_libraries(test_params PRIVATE hsvm_core)
target_compile_options(test_params PRIVATE -Wall -Wextra)

add_executable(test_isa tests/test_isa.cpp)
target_link_libraries(test_isa PRIVATE hsvm_core)
target_compile_options(test_isa PRIVATE -Wall -Wextra)

add_executable(test_machine tests/test_machine.cpp)
target_link_libraries(test_machine PRIVATE hsvm_core)
target_compile_options(test_machine PRIVATE -Wall -Wextra)

add_executable(test_linear tests/test_linear.cpp)
target_link_libraries(test_linear PRIVATE hsvm_core)
target_compile_options(test_linear PRIVATE -Wall -Wextra)

add_executable(test_psi tests/test_psi.cpp)
target_link_libraries(test_psi PRIVATE hsvm_core)
target_compile_options(test_psi PRIVATE -Wall -Wextra)

add_executable(test_mir tests/test_mir.cpp src/mir.cpp)
target_link_libraries(test_mir PRIVATE hsvm_core)
add_test(NAME mir COMMAND test_mir)

add_executable(test_semantics tests/test_semantics.cpp)
target_link_libraries(test_semantics PRIVATE hsvm_core)
add_test(NAME semantics COMMAND test_semantics)

add_executable(test_diff tests/test_diff.cpp)
target_link_libraries(test_diff PRIVATE hsvm_core)
add_test(NAME diff COMMAND test_diff)

add_executable(test_lower_regs tests/test_lower_regs.cpp src/lower.cpp src/mir.cpp)
target_link_libraries(test_lower_regs PRIVATE hsvm_core)
add_test(NAME lower_regs COMMAND test_lower_regs)

add_executable(test_lower_full tests/test_lower_full.cpp src/lower.cpp src/mir.cpp)
target_link_libraries(test_lower_full PRIVATE hsvm_core)
add_test(NAME lower_full COMMAND test_lower_full)

add_executable(test_modenc tests/test_modenc.cpp)
target_link_libraries(test_modenc PRIVATE hsvm_core)
target_compile_options(test_modenc PRIVATE -Wall -Wextra)

add_executable(test_c6 tests/test_c6.cpp)
target_link_libraries(test_c6 PRIVATE hsvm_core)
target_compile_options(test_c6 PRIVATE -Wall -Wextra)

add_executable(test_model tests/test_model.cpp)
target_link_libraries(test_model PRIVATE hsvm_core)
target_compile_options(test_model PRIVATE -Wall -Wextra)

add_test(NAME smoke COMMAND test_smoke)
add_test(NAME gf2 COMMAND test_gf2)
add_test(NAME params COMMAND test_params)
add_test(NAME isa COMMAND test_isa)
add_test(NAME machine COMMAND test_machine)
add_test(NAME linear COMMAND test_linear)
add_test(NAME psi COMMAND test_psi)
add_test(NAME model COMMAND test_model)
add_test(NAME modenc COMMAND test_modenc)
add_test(NAME ddt_normalization COMMAND hsvm_ddt)
add_test(NAME affine_normalization COMMAND hsvm_affine_recover)
add_test(NAME c6 COMMAND test_c6)

# --- Python-side checks (stdlib only) --------------------------------------
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME params_json
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_params_json.py
                   $<TARGET_FILE:hsvm_params>)
  add_test(NAME protocol
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_protocol.py
                   ${CMAKE_CURRENT_SOURCE_DIR}/protocol.json)
  add_test(NAME protocol_mutations
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_protocol.py
                   $<TARGET_FILE:hsvm_params>)
  add_test(NAME report
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_report.py)
  add_test(NAME isa_sync
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tools/sync_isa.py --check)
  # Evidence-chain audit: hashes reproduce, every report resolves and traces to
  # its raw logs, and the judges reject degenerate/lying points.
  add_test(NAME whitebox_audit
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/scripts/whitebox_audit.py)
endif()
