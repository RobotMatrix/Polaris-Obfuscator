#pragma once

#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

namespace polaris {

// Stage 5 (V-08): lower HSV bytecode held in @hsvm.bytecode into native IR for
// the function @hsvm_entry. Register-class opcodes only in this slice; the pass
// refuses anything else with a fatal error rather than miscompiling it.
struct HSVMLowering : PassInfoMixin<HSVMLowering> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }
};

}; // namespace polaris
