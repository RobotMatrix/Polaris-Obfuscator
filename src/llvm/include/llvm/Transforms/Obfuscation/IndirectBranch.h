#pragma once

#include "llvm/Passes/PassBuilder.h"
#include <cstdint>

using namespace llvm;

namespace polaris {
struct IndirectBlockInfo {
  BasicBlock *BB;
  unsigned IndexWithinTable;
  uint64_t RandomKey;
};
struct IndirectBranch : PassInfoMixin<IndirectBranch> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  void process(Function &F);
  static bool isRequired() { return true; }
};

}; // namespace polaris