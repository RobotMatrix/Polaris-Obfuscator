#include "llvm/Transforms/Obfuscation/CustomCC.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Obfuscation/Utils.h"

using namespace llvm;
namespace polaris {
PreservedAnalyses CustomCC::run(Module &M, ModuleAnalysisManager &AM) {
  Triple TargetTriple(M.getTargetTriple());
  if (!TargetTriple.isX86()) {
    report_fatal_error(Twine("ccc is implemented only for x86; this target is ") +
                       TargetTriple.str());
  }
  static const CallingConv::ID ObfuCCs[] = {
      CallingConv::Obfu1, CallingConv::Obfu2, CallingConv::Obfu3,
      CallingConv::Obfu4, CallingConv::Obfu5, CallingConv::Obfu6,
      CallingConv::Obfu7, CallingConv::Obfu8};
  for (Function &F : M) {
    if (readAnnotate(F).find("customcc") != std::string::npos || (readPolicyMatch(F) && policyHasPass("ccc"))) {
      CallingConv::ID CC = ObfuCCs[getRandomNumber() % std::size(ObfuCCs)];
      F.setCallingConv(CC);
      FixInstrCallingConv(M, F, CC);
    }
  }

  return PreservedAnalyses::none();
}
void CustomCC::FixInstrCallingConv(Module &M, Function &Target,
                                   CallingConv::ID CC) {
  for (Function &F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB || CB->isInlineAsm())
          continue;
        if (CB->getCalledFunction() == &Target)
          CB->setCallingConv(CC);
      }
    }
  }
}
} // namespace polaris