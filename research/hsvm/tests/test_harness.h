//===- test_harness.h - minimal CHECK / summary helpers -------------------===//
//
// Same shape as polaris-secure-sdk/tests/test_harness.h so the two codebases
// feel alike: no external test framework, explicit PASS/FAIL lines, and a
// non-zero exit status on failure (ctest reads it).
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_TEST_HARNESS_H
#define HSV_M_TEST_HARNESS_H

#include <cstdio>

namespace hsvm_test {

inline int &passes() {
  static int n = 0;
  return n;
}
inline int &failures() {
  static int n = 0;
  return n;
}

inline int summary(const char *suite) {
  std::printf("== %s: %d pass, %d fail ==\n", suite, passes(), failures());
  return failures() == 0 ? 0 : 1;
}

} // namespace hsvm_test

#define CHECK(cond, name)                                                      \
  do {                                                                         \
    if (cond) {                                                                \
      std::printf("  [PASS] %s\n", name);                                      \
      ++hsvm_test::passes();                                                   \
    } else {                                                                   \
      std::printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__);         \
      ++hsvm_test::failures();                                                 \
    }                                                                          \
  } while (0)

#endif // HSV_M_TEST_HARNESS_H
